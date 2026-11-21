# silent-harvest — techniques, ATT&CK mapping, detection

Each stage of the implant mapped to the technique it uses and the telemetry a
defender can key on. Written from the implementation; the "observed" notes are
the "observed" notes are what actually happened on the development box
(a current Windows 11-era test VM, unelevated user, Chrome + Brave +
Firefox installed, Chrome running).

## Stage map

| # | Stage | APIs | ATT&CK |
|---|---|---|---|
| 1 | Privilege arm | `OpenProcessToken`, `LookupPrivilegeValueW`, `AdjustTokenPrivileges` | T1134 (token manipulation) |
| 2 | Protected-registry read | `NtOpenKeyEx(REG_OPTION_BACKUP_RESTORE)`, `RegQueryMultipleValuesW`, `RegEnumKeyExW`, `RegQueryInfoKeyW` | T1003.002 (SAM), T1003.004 (LSA secrets) |
| 3 | Hive copies | `esentutl.exe /y /vss` (in-box, VSS) | T1003.002/.004, T1006 |
| 4 | Browser artifacts | `CreateFileW(FILE_FLAG_BACKUP_SEMANTICS, share-all)`, `CryptUnprotectData` | T1555.003 (Chromium), T1555.005 (Firefox), T1552.01 (DPAPI) |
| 5 | Locked-file read | `NtQuerySystemInformation(SystemExtendedHandleInformation)`, `DuplicateHandle`, `ReadFile` | T1218-free… none official; handle hijack/dup |
| 6 | C2 exfil | `HttpWebRequest` POST, AES-256-GCM (CNG `BCrypt*`) | T1041 (exfil over C2), T1573.002 (encrypted channel) |
| 7 | Linux: browsers/keys/keyring | plain reads, `secret-tool` (D-Bus Secret Service) | T1555.003/.005, T1552.01, T1003.008 (shadow), T1552.04 (private keys) |

## The registry technique in this codebase

The article's two steps, exactly as implemented in `implant/Util.cs`
(`ReadKeyValues`):

1. **Open with backup intent.** `NtOpenKeyEx` with
   `OpenOptions = REG_OPTION_BACKUP_RESTORE (0x4)` and `DesiredAccess =
   KEY_READ` against `\Registry\Machine\SAM\...` / `\Registry\Machine\SECURITY\...`.
   With `SeBackupPrivilege` enabled in the token, the kernel skips the normal
   ACL check. Without the privilege this open fails `STATUS_ACCESS_DENIED`
   *even on world-readable keys* — it is a privilege-checked path, not a
   fallback — so the code retries once without the flag to still collect
   readable-SYSTEM material (and records which path succeeded in `_status`).
2. **Bulk-read through the rare API.** One `RegQueryMultipleValuesW` call per
   key reads all requested values into a single buffer — not
   `RegQueryValueExW`, which is the API EDR hooks. Values come back as
   `VALENTW` entries pointing into that buffer.

What gets read:

- `HKLM\SAM\SAM\Domains\Account` value `F`, then `...\Users\{RID}` `F`/`V`
  per enumerated RID (per-user hash material, still encrypted with the
  syskey-derived key — decrypted offline from the hive copies).
- `HKLM\SECURITY\Policy\Secrets\{name}\CurrVal` for every enumerated secret
  (service account passwords, DPAPI_SYSTEM, etc.).
- `HKLM\SECURITY\Cache\NL$1..10` (DCC2 cached domain creds) + `NL$Control`.
- `HKLM\SYSTEM\ControlSet00N\Control\Lsa\{JD,Skew1,GBG,Data}` — the syskey
  bootkey components are stored as the **key class names** (not values!),
  read with `RegQueryInfoKeyW`. The parser concatenates and descrambles them
  (perm `[8,5,4,2,11,9,13,3,0,10,1,15,14,6,7,12]`) into the 16-byte bootkey.

Observed on an unelevated test account: bootkey components read OK (fallback
open), bootkey assembled and reported; SAM/SECURITY correctly denied.
Elevated, the same code paths return the protected values.

## Browser handling

- Local State → regex `encrypted_key` → strip 5-byte `DPAPI` prefix →
  `CryptUnprotectData` → 32-byte AES key (os_crypt). `app_bound_encrypted_key`
  is exfiltrated raw for offline work.
- Cookies v114+ live at `<profile>\Network\Cookies`.
- Chrome holds its Cookies DB with no share access while running. Read path:
  normal `CreateFileW` (share-all) → on sharing violation, walk the system
  handle table (`SystemExtendedHandleInformation`, 40-byte x64 entries,
  `ObjectTypeIndex` at +30, filter `FILE_READ_DATA` bit 0 — GENERIC_READ is
  mapped to FILE_GENERIC_READ in granted-access so bit-31 checks reject
  everything), duplicate the owner's handle into the process
  (`DuplicateHandle`, `DUPLICATE_SAME_ACCESS`), `NtQueryObject` name-match in
  a sacrificial thread with 200 ms timeout (named-pipe deadlock), then
  `SetFilePointerEx` save/seek-0/read/restore — the pointer lives in the
  shared FILE_OBJECT, so restoring keeps the owner consistent.
  Observed: 1,015,808-byte live Chrome Cookies DB read this way while Chrome
  was running.
- Blob versions: `v10` = AES-256-GCM(os_crypt key), decrypts server-side;
  `v11`/`v20` = app-bound (elevation-service key), counted and exfiltrated
  raw with the ABE blob.

## Linux specifics (`linux/sh_harvest.py`)

There is no DPAPI on Linux; the protection map is per-desktop:

| store | what it holds | how this tool gets it |
|---|---|---|
| Secret Service (GNOME Keyring / KWallet via D-Bus) | chromium "Safe Storage" password (v11 blobs), app secrets | `secret-tool lookup` (v1+v2 schemas) when the session keyring is unlocked; raw `~/.local/share/keyring/*` files exfiltrated regardless |
| chromium fallback | v10 blobs | hardcoded `"peanuts"` password |
| NSS (Firefox) | key4.db-wrapped 3DES login key | key4.db + logins.json/logins.db exfiltrated — same parser as Windows |
| filesystem | `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.netrc`, `~/.git-credentials`, `~/.docker`, `~/.kube`, histories | plain reads (user owns them) |
| root-only | `/etc/shadow`, NetworkManager psk | plain reads when euid=0 |

Blob scheme difference that matters for tooling: **Linux/macOS v10/v11 are not
GCM** — `blob = "v1x" + AES-128-CBC` where key =
`PBKDF2-HMAC-SHA1(password, b"saltysalt", 1 iter, 16)` and IV is 16 spaces,
PKCS7-padded. Windows v10 is AES-256-GCM with the DPAPI key. Same three-byte
prefix, different cipher — the parser dispatches on the victim `platform`
field. `v20` on Linux (new app-bound generation) is treated like Windows v20:
exfiltrate, don't decrypt.

DBSC (Chrome ≥145): enrolled sites bind session cookies to device-held keys;
stolen cookies decrypt but fail replay from other devices. Not a collection
problem — a loot-valuation problem.

Linux detection surface: auditd/eBPF rules on `open()` of
`~/.mozilla/*/key4.db`, `Network/Cookies`, `Login Data` from non-browser
processes; D-Bus monitor on Secret Service sessions opened by unexpected
callers; outbound single-large-POST with the `SHV1` prefix; process
lineage (python3 from a browser-download/Fonts-writable path).

## Container format

See `server/shcrypto.py` docstring. HKDF-SHA256 over the PSK with a random
per-bundle salt, AES-256-GCM via CNG `BCryptEncrypt` with
`BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO` (note: `cbData` is `ULONGLONG` — 8
bytes; a 4-byte field there fails with `STATUS_INVALID_PARAMETER` and cost an
hour of probing). Implant↔collector interop verified with real traffic.

## Detection notes (defender view)

Mirroring the source article, from what this tool actually does:

- **Event 4672 / privilege use**: a non-backup process enabling
  `SeBackupPrivilege` (`AdjustTokenPrivileges`) is the loudest step. Correlate
  with the parent process, not just the event.
- **Backup-intent registry opens**: `NtOpenKeyEx` with
  `REG_OPTION_BACKUP_RESTORE` from processes that are not backup software.
  Requires ETW/kernel telemetry on ntdll — usermode API hooks on advapi32
  won't see it (that is the point of the technique).
- **`RegQueryMultipleValuesW`** touching `HKLM\SAM` / `HKLM\SECURITY`. Rare
  API; nearly zero benign callers per host per week.
- **`RegQueryInfoKeyW` class reads** on `Lsa\{JD,Skew1,GBG,Data}` — classic
  syskey retrieval, tiny signal, old as creddump.
- **esentutl /vss** touching `\Device\HarddiskVolumeShadowCopy*\Windows\System32\config\*`.
- **Handle table enumeration** (`NtQuerySystemInformation(0x40)` with a
  multi-MB buffer) followed by cross-process `DuplicateHandle` bursts —
  thousands of duplicates in a second is not normal app behavior.
- **Single large POST with a 6-byte `SHV1` plaintext prefix** to an
  unexpected host; everything else is opaque ciphertext. An optional
  `X-SH-Auth` header may accompany it (constant value, replayable).
- **DPAPI**: `CryptUnprotectData` on blobs whose plaintext is a 32-byte
  high-entropy key, from a process with no browser lineage.

## Dev-box verification log (what actually ran, sanitized)

- `shcrypto.py` self-test: pack/unpack roundtrip + wrong-PSK rejection.
- `synth_firefox.py`: PBES2 ASN.1 parse → PBKDF2-HMAC-SHA256 → a11 unwrap →
  3DES-CBC field decrypt, 2/2 known values recovered; ASN.1 walker validated
  against a real NSS key4.db dump first.
- `synth_chromium.py`: DPAPI(wrap/unwrap) + v10 AES-GCM cookies, password,
  credit card, autofill, Netscape export — all recovered through
  `parse_chromium`.
- `synth_linux.py`: full Linux implant run over a synthetic home (chrome v10
  `peanuts` cookie, brave v10 keyring-password login, firefox key4/logins,
  SSH/GPG keys, AWS creds, keyring file, history) → SHV1 container →
  platform-aware parser — all recovered; plus a live HTTP exfil variant.
- Live unelevated E2E (both debug and release builds): registry technique
  (bootkey assembled), browser harvest (keys recovered, Chrome Cookies via
  handle-dup while running, Brave/autofill/523 entries), AES-GCM container
  over HTTP to the local collector, decrypted and parsed server-side.
- Not exercised on-box (needs elevation/domain): SeBackupPrivilege-armed
  SAM/SECURITY reads, esentutl hive copies, secretsdump of real hives.
