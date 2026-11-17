# Indicators of Compromise

Indicators below describe the **original malware and observed infrastructure**. Modified research-build hashes are listed separately and must not be confused with the original samples.

Observation date: **2026-11-17**.

## Original file indicators — not distributed in this repository

| Type | Value |
|---|---|
| Stage-1 filename used for analysis | `scammers_apk_file.apk` |
| Stage-1 SHA-256 | `8298a151bde2a84255d32f495f7c2baa85e60b466dbd33f22951e7e59de5c753` |
| Stage-1 size | 1,323,012 bytes |
| Stage-1 package | `it.sharp.hidden` |
| Stage-1 version | `95.95.36` / versionCode `16` |
| Encrypted payload asset | `assets/ylx0` |
| Encrypted asset size | 371,344 bytes |
| Asset transformation | Cyclic XOR, then AES-128-ECB |
| Asset key | `TIwcHVIsbeO13zlm` |
| Recovered stage-2 filename | `p_toydan8102.apk` |
| Stage-2 SHA-256 | `55d6ac453a19ce6bedd30b16173e18dc74cc0f7a4b5f2579a8cc8b2105df22ba` |
| Stage-2 size | 371,330 bytes |
| Stage-2 package | `ai.your.tundra` |
| Stage-2 version | `4.76.57` / versionCode `81029621` |
| Stage-2 signing-certificate subject | `CN=com.android.bluetooth.services` |
| Stage-2 certificate SAN | `android@android.com` |

## Modified research artifacts published here

| Artifact | Size | SHA-256 |
|---|---:|---|
| `scammers_apk_file.apk` | 750,283 bytes | `224ad223b2ea6fa56b02ae82411cb5b20f57eb1a5a2f22165f6f4e0b0bcc900a` |
| `p_toydan8102.apk` | 424,459 bytes | `5b5880673fa66b9265049d844c057f860f5177c15aef293ab19c86799a060749` |
| Shared research signer | — | `CN=RESEARCH-MODIFIED-SAMPLE, OU=MalwareAnalysis, O=DefensiveResearch` |

## Network indicators

| Type | Value |
|---|---|
| Observed C2 domain | `orehi.top` |
| Endpoint | `POST https://orehi.top/` |
| Observed IPv4 | `188.114.96.3`, `188.114.97.3` — Cloudflare |
| Observed IPv6 | `2a06:98c1:3120::c`, `2a06:98c1:3121::c` — Cloudflare |
| Content type | `application/json` |
| Request headers | `X-Timestamp`, `X-Signature` |
| Body shape | `{"result":"<base64 ciphertext>"}` |
| Cipher | AES-256-GCM, 128-bit authentication tag |
| Key derivation | `SHA-256("2fCpMDVTAE3ZbHHvqJM9T1xIpgJGKedY")` |
| Fixed IV derivation | First 12 bytes of `SHA-256("OTpkz8YYPT3Crz9m")` |
| Signature salt | `DdQ3sfVT0RgviD358cpE0k` |
| Signature input | Raw body + `|` + timestamp + `|` + salt |
| Domain-rotation response field | `rV` |

Cloudflare addresses are point-in-time observations, not origin-server attribution. Domain and address reputation can change; use the full request and host-artifact context rather than blocking solely on shared IP addresses.

## Encrypted C2 path tokens

| Token | Function |
|---|---|
| `27ImuEHa5uG1v6lVFLrM93GuLPs8Yydx` | Registration / new installation |
| `XqWEmMjUzXu5o7YtCOkWOwaXCUqRwfjb` | SMS batch exfiltration |
| `PNv7wk1KBY0WwQ4KrK2Tf3WhvVH4rRbl` | USSD result exfiltration |
| `a9GjG2WtdB89Sa1tLY2IdN8wpHdvcg6D` | Polling / battery state |
| `NCRPHMNZxwFRnGYZjhtxuDDmekSvKSmGtCGfIyslNx` | Device-state push |
| `GDgCblEzMeLCVeCoTOvEZOidczHuaCgbTYWPTXtzfw` | Phone / SIM inventory |

These tokens occur inside decrypted request plaintext, not in the visible URL path.

## Telegram indicator

| Type | Value |
|---|---|
| Receiving chat ID | `8731793636` |
| Bot username | Unknown |
| Bot token | Not present in the analyzed sample |

A numeric chat ID alone does not establish an operator identity.

## Host artifacts

| Type | Value |
|---|---|
| C2 preferences file | `eva_requests` |
| Domain preference key | `main_domain` |
| SMS queue preferences file | `eva_sms_queue` |
| SMS queue key | `pending` |
| JobScheduler IDs | `2001`, `2002` |
| Build tag | `toydan8102` |
| Version tag | `evangelion_version_3` |
| In-sample note handle | `wretchedcat` |
| SMS receiver | `ai.your.tundra.Elqetortor` |
| Boot receiver | `ai.your.tundra.VaskuVael94` |
| Notification listener | `ai.your.tundra.FaQe34` |
| Foreground service | `ai.your.tundra.Intetrarbe` |
| Job service | `ai.your.tundra.TorRoya` |

## Exfiltrated field names

```text
androidId
deviceName
sdkVersion
display
chatId
buildVersion
version
forReversers
apps
battery
listPhones
messages
simId
operator
sender
message
ussdCode
response
```

## Detection notes

- Treat unknown-source installation of `it.sharp.hidden` followed by `ai.your.tundra` as a high-confidence chain indicator.
- Inspect priority SMS receivers, enabled notification listeners, device-protected preference files, and scheduled jobs `2001` / `2002`.
- Network detection should combine TLS SNI, `POST /`, JSON body shape, and the two custom headers. The plaintext path tokens require decryption or endpoint telemetry.
- The published research APKs intentionally retain many code-level strings for analysis. A code-string-only signature can therefore match the neutralized builds; use the original hashes when identifying live samples.

## References

- Group-IB, *Choose Your Fighter: A New Stage in the Evolution of Android SMS Stealers in Uzbekistan*, December 2025.
- Starlabs ACT, Android C2 Tracker, family entry *EVANGELION (provisional)*.
