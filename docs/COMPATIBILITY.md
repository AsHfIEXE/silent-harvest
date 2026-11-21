# Compatibility matrix

What is expected to work where, per component. "partial" rows explain the
boundary condition. Verified = covered by `test/` (runs in CI on
windows-latest + ubuntu-latest, Python 3.9–3.13); manual = verified by hand
on the dev box only.

## Operator side (collector + parsers)

| capability | Windows | Linux | macOS | notes |
|---|---|---|---|---|
| collector | ✔ | ✔ | ✔ | stdlib only |
| parse_loot (chromium v10 windows scheme) | ✔ | ✔ | ✔ | needs `cryptography` |
| parse_loot (chromium v10/v11 linux scheme) | ✔ | ✔ | ✔ | |
| parse_loot (firefox key4/logins) | ✔ | ✔ | ✔ | |
| parse_loot (linux artifacts) | ✔ | ✔ | ✔ | |
| secretsdump integration | ✔ | ✔ | ✔ | optional `impacket` |
| output permission hardening (0600) | n/a | ✔ | ✔ | no-op on Windows |

## Windows implant (C#, .NET Framework 4.x)

| capability | Win 8.1 | Win 10 | Win 11 | Server 2016+ | condition |
|---|---|---|---|---|---|
| build via in-box csc.exe | ✔ | ✔ | ✔ | ✔ | no SDK needed |
| registry technique (readable keys) | ✔ | ✔ | ✔ | ✔ | unelevated |
| SAM/LSA secrets via backup-intent open | ✔ | ✔ | ✔ | ✔ | **elevated only** |
| hive copies (esentutl /vss) | ✔ | ✔ | ✔ | ✔ | elevated + VSS service |
| chromium DPAPI keys + v10 blobs | ✔ | ✔ | ✔ | ✔ | v11/v20 app-bound: exfil-only |
| handle-dup of locked DBs | ✔ | ✔ | ✔ | ✔ | x64 only (32-bit implant skips it) |
| firefox artifacts | ✔ | ✔ | ✔ | ✔ | |
| TLS verify / cert pin | ✔ | ✔ | ✔ | ✔ | TLS 1.2 forced |

Verified: Windows 11-era box (manual + interop test in CI on windows-latest).

## Linux implant (python3)

| capability | Ubuntu/Debian | Fedora | Arch | condition |
|---|---|---|---|---|
| browser artifacts | ✔ | ✔ | ✔ | python3 present |
| chromium keyring password (v11 blobs) | ✔ | ✔ | ✔ | unlocked keyring + `secret-tool` |
| chromium "peanuts" fallback (v10) | ✔ | ✔ | ✔ | always |
| firefox classic decrypt | ✔ | ✔ | ✔ | server-side |
| ssh/gpg/aws/... keys | ✔ | ✔ | ✔ | user-readable files |
| /etc/shadow + NM psk | ✔ | ✔ | ✔ | **root only** |
| AES-GCM | ✔ | ✔ | ✔ | `cryptography` OR openssl libcrypto |
| TLS verify / cert pin | ✔ | ✔ | ✔ | |

Verified: synthetic-home roundtrip (CI, both OSes).

## Known non-goals / not covered

- macOS implant (the parser already understands the macOS chromium scheme;
  no collection binary).
- 32-bit Windows implant handle-dup path (struct layout differs).
- Chromium app-bound v11/v20 decryption in user mode (by design — see
  README "Capabilities & limitations").
