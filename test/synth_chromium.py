"""Synthetic Chromium fixture generator + parser round-trip test.

Builds a fake browser harvest exactly the way real artifacts look:
  - Local State with os_crypt.encrypted_key = b64("DPAPI" || CryptProtectData(key))
  - Cookies sqlite with v10 blobs: b"v10" + iv(12) + AES-256-GCM ct + tag(16)
  - Login Data sqlite with password_value v10 blobs
  - Web Data sqlite with autofill + an encrypted card

Then runs server/parse_loot.parse_chromium over the parts and asserts the
known values come back. This validates the classic (pre-app-bound) chain
byte-for-byte even though this test box's browsers are all v20-era.
"""
import base64
import ctypes
import ctypes.wintypes as wt
import json
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "server"))
import parse_loot as P

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CRYPTPROTECT_UI_FORBIDDEN = 0x01


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def dpapi_protect(data):
    """CryptProtectData in the CURRENT user context (same as Chrome does)."""
    inbuf = ctypes.create_string_buffer(data, len(data))
    bin_ = DATA_BLOB(len(data), ctypes.cast(inbuf, ctypes.POINTER(ctypes.c_char)))
    bout = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(bin_), None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(bout)):
        raise OSError("CryptProtectData failed")
    try:
        return ctypes.string_at(bout.pbData, bout.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(bout.pbData)


def v10_blob(key, plaintext):
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, plaintext, None)
    return b"v10" + iv + ct


def make_db(path, schema, inserts):
    db = sqlite3.connect(path)
    db.executescript(schema)
    for sql, data in inserts:
        db.executemany(sql, data)
    db.commit()
    db.close()
    return open(path, "rb").read()


def main():
    key = os.urandom(32)
    tmp = tempfile.mkdtemp(prefix="sh_chrome_")

    cookies_schema = """
    CREATE TABLE cookies (
        host_key TEXT NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL,
        path TEXT NOT NULL, expires_utc INTEGER NOT NULL, is_secure INTEGER,
        is_httponly INTEGER, encrypted_value BLOB);
    """
    cookie_rows = [
        ("INSERT INTO cookies VALUES (?,?,?,?,?,?,?,?)", [
            (".example.org", "sid", "", "/", 99999999999999999, 1, 1,
             v10_blob(key, b"S3SSION-COOKIE-VALUE")),
            ("site.test", "theme", "", "/", 0, 0, 0,
             v10_blob(key, b"dark")),
        ])
    ]
    cookies_db = make_db(os.path.join(tmp, "C"), cookies_schema, cookie_rows)

    logins_schema = """
    CREATE TABLE logins (origin_url TEXT, action_url TEXT, username_element TEXT,
        username_value TEXT, password_element TEXT, password_value BLOB,
        date_created INTEGER);
    """
    logins_rows = [
        ("INSERT INTO logins VALUES (?,?,?,?,?,?,?)", [
            ("https://example.org/login", "https://example.org/do", "u",
             "user@example.org", "p", v10_blob(key, b"SuperSecret123!"),
             13000000000000000),
        ])
    ]
    logins_db = make_db(os.path.join(tmp, "L"), logins_schema, logins_rows)

    web_schema = """
    CREATE TABLE autofill (name TEXT, value TEXT, value_lower TEXT,
        date_created INTEGER, count INTEGER);
    CREATE TABLE credit_cards (guid TEXT, name_on_card TEXT, expiration_month INTEGER,
        expiration_year INTEGER, card_number_encrypted BLOB, nickname TEXT);
    """
    web_rows = [
        ("INSERT INTO autofill VALUES (?,?,?,?,?)", [
            ("email", "user@example.org", "user@example.org", 1, 3)]),
        ("INSERT INTO credit_cards VALUES (?,?,?,?,?,?)", [
            ("g1", "John Doe", 12, 2030, v10_blob(key, b"4111111111111111"), "visa")]),
    ]
    web_db = make_db(os.path.join(tmp, "W"), web_schema, web_rows)

    local_state = {"os_crypt": {"encrypted_key":
                   base64.b64encode(b"DPAPI" + dpapi_protect(key)).decode()}}
    ls_bytes = json.dumps(local_state).encode()
    # on non-Windows CI runners DPAPI is unavailable; the Local State part is
    # optional for the parser (the key arrives as aeskey.bin regardless)

    parts = {
        "b:test/aeskey.bin": dpapi_protect(key)[0:0] or key,  # key part = raw 32B (implant unwraps on host)
        "b:test/Default/Cookies": cookies_db,
        "b:test/Default/LoginData": logins_db,
        "b:test/Default/WebData": web_db,
    }
    if sys.platform.startswith("win"):
        parts["b:test/LocalState"] = ls_bytes

    report = []
    creds = {}
    P.COOKIE_DIR = tmp
    P.parse_chromium(parts, report, creds)

    print("\n".join(report))
    cookies = [c for c in creds.get("cookies", []) if c["decrypted"]]
    assert any(c["name"] == "sid" and c["value"] == "S3SSION-COOKIE-VALUE"
               for c in cookies), "cookie decrypt failed"
    pw = creds.get("passwords", [])
    assert any(p["password"] == "SuperSecret123!" and p["user"] == "user@example.org"
               for p in pw), "login decrypt failed"
    cards = creds.get("cards", [])
    assert any(c["number"] == "4111111111111111" for c in cards), "card decrypt failed"
    af = creds.get("autofill", [])
    assert any(a["value"] == "user@example.org" for a in af), "autofill missing"
    ns = os.path.join(tmp, "cookies_test_Default.txt")
    assert os.path.exists(ns) and "S3SSION-COOKIE-VALUE" in open(ns).read(), "netscape file missing"
    print("\nchromium v10 roundtrip OK: cookie+login+card+autofill+netscape all decrypted")


if __name__ == "__main__":
    main()
