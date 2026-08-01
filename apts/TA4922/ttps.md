# MITRE ATT&CK Mapping

This mapping uses the Enterprise ATT&CK taxonomy available on July 30, 2026.
Every mapping is grounded in code, configuration, or artifacts recovered from
the local samples. The scope distinguishes locally confirmed implementation
from capability-only code and does not infer successful runtime use.

ATT&CK now places DLL side-loading under
[`T1574.001` Hijack Execution Flow: DLL](https://attack.mitre.org/techniques/T1574/001/).
Earlier ATT&CK mappings may identify DLL side-loading as `T1574.002`.

## Cruciferra Execution and Stealth

| ATT&CK ID | Technique | Evidence | Scope |
| --- | --- | --- | --- |
| `T1574.001` | Hijack Execution Flow: DLL | Two host executables with embedded Authenticode signatures load adjacent malicious `Secur32.dll` files and resolve `GetUserNameExW` | Locally confirmed side-loading relationship in the exact 33863 chain and related 119863 image; runtime use unobserved |
| `T1027.001` | Obfuscated Files or Information: Binary Padding | DLLs contain approximately 323–370 MB of repeated `JKHI`/`jkhi` overlay data | Locally confirmed |
| `T1027.013` | Obfuscated Files or Information: Encrypted/Encoded File | Payloads and driver are stored as a long `P`–`_` Base16 container and custom-ARX ciphertext | Locally confirmed |
| `T1140` | Deobfuscate/Decode Files or Information | Loader decodes the nibble alphabet, parses the container, expands a key, and decrypts its entries | Locally confirmed implementation; runtime use unobserved |
| `T1106` | Native API | Native calls support section creation, file disposition changes, process construction, and ghost execution | Locally confirmed implementation in the related 119863 image; runtime use unobserved |
| `T1055` | Process Injection | Custom Process Ghosting writes a temporary image, creates a `SEC_IMAGE` section, marks the backing file for deletion, and redirects execution into a new process | Locally confirmed implementation in the related 119863 image; mapped to the parent because ATT&CK has no exact Process Ghosting sub-technique |

The custom payload cipher is a 24-round ARX stream transform. Its
`16/12/8/7` rotations resemble ChaCha, but the implementation is not
standard ChaCha and is not mapped or detected as such.

## Privilege Escalation and Defense Impairment

| ATT&CK ID | Technique | Evidence | Scope |
| --- | --- | --- | --- |
| `T1548.002` | Abuse Elevation Control Mechanism: Bypass User Account Control | Loader contains a CMSTPLUA-style COM Elevation Moniker and an enabled `uac_bypass` feature | Locally confirmed code and feature setting; runtime use unobserved |
| `T1543.003` | Create or Modify System Process: Windows Service | Loader creates and starts `PcaSvc_procmon` for `C:\Windows\System32\drivers\pcdhost.sys` | Locally confirmed implementation; runtime use unobserved |
| `T1057` | Process Discovery | Loader enumerates running processes and compares them with 138 security-product process names | Locally confirmed implementation; runtime use unobserved |
| `T1518.001` | Software Discovery: Security Software Discovery | 33863 loader consumes a list of 138 security-product process names | Locally confirmed |
| `T1687` | Exploitation for Defense Impairment | Loader deploys vulnerable `ardrv.sys` and invokes CVE-2026-36425 IOCTL `0x2420031` to terminate selected processes | Locally confirmed end-to-end implementation; runtime use unobserved |
| `T1562.001` | Impair Defenses: Disable or Modify Tools | `edr_killer` is enabled; the driver handle, PID buffer, IOCTL, and resolved `DeviceIoControl` call are linked in code | Locally confirmed implementation; runtime use unobserved |

For `T1687`, the local call chain provides implementation evidence beyond a
string-only inference. The loader resolves `DeviceIoControl`, calls a getter
that returns `0x2420031`, places that value in the IOCTL argument, and invokes
the resolved API with the `ardrv` handle and PID buffer. The current ATT&CK
description for
[`T1687` Exploitation for Defense Impairment](https://attack.mitre.org/techniques/T1687/)
specifically covers exploiting vulnerabilities to terminate security
processes or otherwise degrade defenses.

## Command and Control

| ATT&CK ID | Technique | Evidence | Scope |
| --- | --- | --- | --- |
| `T1095` | Non-Application Layer Protocol | Client uses a direct non-HTTP TCP socket on port 4449, wraps it in TLS, and carries MessagePack application records | Locally confirmed implementation; runtime use unobserved |
| `T1573.002` | Encrypted Channel: Asymmetric Cryptography | The direct TCP connection is wrapped in TLS and pins an embedded RSA certificate; a separate embedded RSA signature authenticates the configuration key | Locally confirmed implementation; runtime use unobserved |
| `T1105` | Ingress Tool Transfer | Recovered client contains send-file and in-memory payload/plugin handlers | Capability only |
| `T1090` | Proxy | Recovered client contains a reverse-proxy plugin; its deployment topology was not observed | Capability only |

The four-byte little-endian message length and MessagePack body are carried
within TLS and are not normally visible to a network sensor without
decryption. The certificate fingerprints remain observable during the
TLS 1.0 handshake and provide a sample-linked, protocol-independent network
pivot.

## VenomRAT-Derived Client Capabilities

The following mappings are **Capability only** and describe code present in
the recovered assembly. They do not establish that TA4922 operators invoked
the functions.

| ATT&CK ID | Technique | Recovered capability |
| --- | --- | --- |
| `T1056.001` | Input Capture: Keylogging | Keylogger plugin |
| `T1113` | Screen Capture | Screenshot and remote-desktop handlers |
| `T1123` | Audio Capture | Remote audio handler |
| `T1125` | Video Capture | Camera handler |
| `T1057` | Process Discovery | Process-manager plugin |
| `T1083` | File and Directory Discovery | File manager and file-search plugins |
| `T1049` | System Network Connections Discovery | Netstat plugin |
| `T1112` | Modify Registry | Remote registry plugin |
| `T1005` | Data from Local System | File, screen, camera, audio, and recovery collection paths |
| `T1555.003` | Credentials from Password Stores: Credentials from Web Browsers | Browser-recovery functionality is present in the plugin set |
| `T1539` | Steal Web Session Cookie | CDP recovery relaunches Chrome/Edge on port 9222 and requests `Network.getAllCookies` |
| `T1055.012` | Process Injection: Process Hollowing | Send-memory plugin creates a suspended process, unmaps its image, writes a PE, changes thread context, and resumes it |
| `T1562.001` | Impair Defenses: Disable or Modify Tools | Embedded ToggleDefender PowerShell resource changes Defender policy, service, notifications, and scan artifacts |

## Analytic Notes

- Mappings supported by direct local static evidence include `T1027.001`,
  `T1027.013`, `T1140`, `T1574.001`, `T1055`, `T1548.002`, `T1543.003`,
  `T1057`, `T1518.001`, `T1687`, `T1562.001`, `T1095`, and `T1573.002`.
- The BYOVD service/device/IOCTL sequence is substantially more specific
  than a generic vulnerable-driver load.
- Payload plugin presence supports validation and hunting. Without
  corroborating telemetry, it does not establish operator activity.
