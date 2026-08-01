# VenomRAT Configuration and Protocol

## Statically Verified Configuration

| Setting | Value | Interpretation |
| --- | --- | --- |
| Hosts | `103.59.103.93,103.97.128.141` | Verbatim decoded C2 address list |
| Ports | `4449` | TCP port used for both host candidates |
| Mutex | `fldnqpgqpzd` | Host or build pivot |
| Group | `Default` | Client grouping label |
| Version | `RAT + hVNC  6.0.9 Cracked By t.me/VidBckup` | VenomRAT/hVNC build label |
| Delay | `1` | Configured client delay value |
| Install | `false` | Client install routine disabled |
| Install folder/file | `%AppData%` / `Wihnup.exe` | Inactive defaults while installation is disabled |
| Pastebin | `null` | No dead-drop configuration |
| Anti-analysis | `false` | Managed-client option disabled |
| Anti-process | `false` | Managed-client option disabled; distinct from native loader's EDR killer |
| BSOD | `false` | Disabled |
| CIS blocking | `false` | Disabled |
| Clipper | `false` | Disabled; wallet fields empty |

The native loader's enabled defense-impairment path and the managed client's
`Anti_Process=false` value apply to separate components. The latter does not
negate the statically confirmed `ardrv.sys` implementation. No runtime
execution was performed.

## Connection Construction

The recovered client performs the following sequence:

1. Open a raw TCP connection to one of the configured IP addresses on
   TCP/4449.
2. Wrap the stream in .NET `SslStream`.
3. Validate the server certificate through `ValidateVenomServer` against the
   embedded pinned certificate.
4. Authenticate as a client with `SslProtocols.Tls` and certificate
   revocation checking disabled.
5. Send and receive framed MessagePack records.

The explicit `SslProtocols.Tls` value corresponds to TLS 1.0 in this .NET API.
The runtime and server may affect negotiation behavior. Static analysis
establishes the configured protocol value but not the version negotiated
during a successful connection.

## Message Framing

Application messages use:

```text
uint32_le message_length
byte[message_length] messagepack_record
```

Fields and packet names are partially obfuscated, including forms such as
`Pac_ket`. A keepalive record uses `PING`.

Because the length and MessagePack body are inside TLS, passive network
detection should prioritize:

- configured destination IP plus TCP/4449;
- the pinned SHA-1/SHA-256/SPKI certificate fingerprints;
- TLS 1.0 from an anomalous client process;
- correlation with the side-loaded host and `PcaSvc_procmon` driver chain.

## Configuration-Key Binding

The client configuration contains:

- a 562-byte DER certificate;
- a 128-byte RSA signature;
- the client configuration master key.

The signature verifies as RSA PKCS#1 v1.5 over the SHA-256 digest of the
master key using the embedded certificate's public key. This verification
cryptographically binds the decoded configuration key to that embedded
certificate; it does not establish ownership of, or successful authentication
to, a specific server.

Certificate pivots:

```text
SHA-256  da8751a11fbd4f9638aab7fbd89ba21d8e1d9661710e7d04f35268bb4e3564ef
SHA-1    811816215363259bb445a45422e60ff5d02c18f5
SPKI     8c1f16f891ec0decbebf06abc4a1d4db64fe5df19c1edaf342b4a0a79ce8922d
Subject  CN=Venom
```

The certificate is embedded in the locally recovered client configuration.
Its `CN=Venom` subject, considered with the locally recovered
`VenomRATByVenom` salt and version banner, supports its use as a
VenomRAT-family pivot. The certificate alone is not sufficient for TA4922
attribution.

## Command and Plugin Surface

Static type and dispatch evidence identifies plugins for:

- reverse proxy;
- file upload/download and in-memory execution;
- process, service, registry, file, and network-connection management;
- remote desktop, screen capture, hVNC, and RunPE;
- camera and audio;
- keylogging and clipboard monitoring;
- browser and application recovery;
- Discord-oriented recovery;
- system and application inventory.

This list describes available protocol actions rather than observed commands.
Dynamic tasking, successful connection, and data exfiltration remain
unverified.

### Reverse-Proxy Packet Schema

The reverse-proxy handler decodes MessagePack, requires
`Pac_ket="REVERSE_PROXY"`, reads a JSON body from `json`, and selects the
operation from integer field `type`:

| Value | Operation | JSON fields |
| ---: | --- | --- |
| 0 | `CONNECT` | `ConnectionId`, `Target`, `Port` |
| 1 | `CONNECTRESPONSE` | `ConnectionId`, `IsConnected`, `LocalAddress`, `LocalPort`, `RemotePort`, `HostName` |
| 2 | `DATA` | `ConnectionId`, `Data` |
| 3 | `DISCONNECT` | `ConnectionId` |
| 4 | `INIT` | Defined in the enum; not dispatched by the recovered reader |

The inner JSON exposes these names only after TLS and MessagePack decoding.
They are suitable for endpoint plaintext telemetry, memory scanning, or
authorized TLS-decryption environments, but not for ordinary passive packet
inspection.

### Browser Recovery

The recovery implementation combines several credential and session sources:

- Chromium `Local State` master-key extraction, Windows DPAPI
  `CryptUnprotectData`, and AES-GCM handling for `v10`/`v11` records;
- Firefox-family NSS loading and `PK11SDR_Decrypt`;
- 35 Chromium-family and eight Gecko-family profile paths, plus Edge;
- a CDP path that terminates Chrome or Edge, relaunches it with
  `--remote-debugging-port=9222 --headless=new`, connects to the local
  DevTools WebSocket, and requests `Network.getAllCookies`.

The path-encryption key decodes to the embedded reference
`https://github.com/LimerBoy/StormKitty`. This establishes a
StormKitty-referencing artifact in the local payload; the reference alone
does not establish code lineage or actor specificity.

### Embedded Resources

`Client.Properties.Resources` contains two analytically significant objects:

| Resource | Size | SHA-256 | Static interpretation |
| --- | ---: | --- | --- |
| `Powershell` | 4,926 UTF-8 bytes | `2225f4056a19536d497630afe921e85f44749259e893611a5e20d58ef0813a47` | Hash of the extracted UTF-8 text; ToggleDefender-referencing script using SilentCleanup UAC bypass logic, notification suppression, Defender policy changes, `MpCmdRun`, and service manipulation |
| `hvnc` | 38,912 | `e0bef7f04afe55b8d90261f6e64a6f7874dccf9f901080bd0c540e637c80f6dc` | PE32 CIL assembly `hvnc`, version 6.0.9.0 |

The carved hVNC component exposes browser-specific Brave, Chrome, Edge, and
Firefox classes, screenshot rendering, window/input control, clipboard
handling, and command processing. Its debug path names the Venom Project
`BigEye Final(2025-04-06) Released` source tree. The component timestamp is
future-dated to 2099 and is not treated as chronology evidence.

## Local Configuration Scope

The C2 addresses, TCP port, mutex, version label, cryptographic material, and
feature settings in this document were recovered from the local managed
payload. Static extraction does not establish current infrastructure
ownership, endpoint availability, successful communication, or independent
TA4922 attribution. Campaign attribution requires separate sample-provenance
evidence.
