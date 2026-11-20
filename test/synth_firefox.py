"""Synthetic classic-Firefox fixture generator + round-trip test.

Builds a key4.db (globalSalt + PBES2 password-check + a11-wrapped 3DES key)
and a logins.json exactly the way NSS lays them out, then runs the parser's
firefox functions over them and asserts the known values come back.

This verifies the ASN.1 walker, the PBKDF2 KDF, the a11 unwrap and the
3DES-CBC field decryption independently of having live Firefox logins.
"""
import base64
import json
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + os.sep + ".." + os.sep + "server")
import parse_loot as P

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding


# ---------------------------------------------------------------- DER encoder
def der(tag, content):
    l = len(content)
    if l < 0x80:
        lenb = bytes([l])
    else:
        raw = l.to_bytes((l.bit_length() + 7) // 8, "big")
        lenb = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + lenb + content


# Exact DER encodings, confirmed byte-for-byte against a real NSS key4.db
OID_BYTES = {
    "1.2.840.113549.1.5.13": bytes.fromhex("2a864886f70d01050d"),    # pkcs5 PBES2
    "1.2.840.113549.1.5.12": bytes.fromhex("2a864886f70d01050c"),    # PBKDF2
    "2.16.840.1.101.3.4.1.42": bytes.fromhex("60864801650304012a"),  # aes256-CBC
    "1.2.840.113549.2.9": bytes.fromhex("2a864886f70d0209"),         # hmacWithSHA256
}


def oid(s):
    return der(0x06, OID_BYTES[s])


OID_PBES2 = "1.2.840.113549.1.5.13"
OID_PBKDF2 = "1.2.840.113549.1.5.12"
OID_AES256CBC = "2.16.840.1.101.3.4.1.42"
OID_HMAC_SHA256 = "1.2.840.113549.2.9"


def pkcs7(data, bs):
    n = bs - (len(data) % bs)
    return data + bytes([n]) * n


def make_pbes2(global_salt, entry_salt, plaintext):
    """Encrypt plaintext the NSS way; returns DER blob."""
    key = P.nss_kdf(global_salt, entry_salt, 1, 32)
    iv = b" " * 16  # NSS quirk: fixed IV of spaces for these wrapped keys
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(pkcs7(plaintext, 16)) + enc.finalize()

    kdfparams = (der(0x04, entry_salt) + der(0x02, b"\x01") +
                 der(0x02, b"\x20") + der(0x30, oid(OID_HMAC_SHA256)))
    kdf = der(0x30, oid(OID_PBKDF2) + der(0x30, kdfparams))
    encscheme = der(0x30, oid(OID_AES256CBC) + der(0x04, iv[:14]))
    params = der(0x30, kdf + encscheme)
    algid = der(0x30, oid(OID_PBES2) + params)
    return der(0x30, algid + der(0x04, ct))


def make_key4(global_salt, check_blob, a11_blob):
    path = os.path.join(tempfile.mkdtemp(prefix="sh_k4_"), "key4.db")
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE metadata (id PRIMARY KEY, item1, item2)")
    db.execute("CREATE TABLE nssPrivate (a11, p11)")
    db.execute("INSERT INTO metadata VALUES ('password', ?, ?)", (global_salt, check_blob))
    db.execute("INSERT INTO nssPrivate VALUES (?, ?)", (a11_blob, b""))
    db.commit()
    db.close()
    return path, open(path, "rb").read()


def make_logins_json(key3des, entries):
    out = {"nextId": 1, "logins": []}
    for host, user, pw in entries:
        def enc_field(s):
            data = s.encode()
            iv = os.urandom(8)
            c = Cipher(algorithms.TripleDES(key3des), modes.CBC(iv)).encryptor()
            ct = c.update(pkcs7(data, 8)) + c.finalize()
            return base64.b64encode(iv + ct).decode()
        out["logins"].append({
            "id": len(out["logins"]) + 1, "hostname": host,
            "formSubmitURL": host, "usernameField": "u", "passwordField": "p",
            "encryptedUsername": enc_field(user),
            "encryptedPassword": enc_field(pw),
        })
    return json.dumps(out).encode()


def main():
    global_salt = os.urandom(20)
    entry_salt_1 = os.urandom(32)
    entry_salt_2 = os.urandom(32)
    key3des = os.urandom(24)

    check_blob = make_pbes2(global_salt, entry_salt_1, b"password-check")
    a11_blob = make_pbes2(global_salt, entry_salt_2, key3des)

    _, key4_bytes = make_key4(global_salt, check_blob, a11_blob)
    known = [("https://example.org", "user@example.org", "S3cretPw!"),
             ("https://github.com", "octocat", "hunter2hunter2")]
    logins_bytes = make_logins_json(key3des, known)

    # ---- run the parser functions over the synthetic artifacts ----
    key, note = P.firefox_key_from_key4(key4_bytes)
    assert key is not None, "key recovery failed: %s" % note
    assert key == key3des, "recovered key mismatch!"
    print("a11 unwrap OK:", note)
    print("3DES key recovered:", key.hex())

    parts = {
        "ff:test/key4.db": key4_bytes,
        "ff:test/logins.json": logins_bytes,
    }
    report = []
    creds = {}
    P.parse_firefox(parts, report, creds)
    print("\n".join(report))
    got = [(c["user"], c["password"]) for c in creds.get("passwords", [])]
    for host, user, pw in known:
        assert (user, pw) in got, "missing %r" % user
    print("\nlogins roundtrip OK: %d/%d fields decrypted with correct values"
          % (len(got), len(known)))


if __name__ == "__main__":
    main()
