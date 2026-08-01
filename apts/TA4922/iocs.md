# Indicators and Analytic Pivots

This report is limited to indicators recovered from, or derived directly
from, the local sample set. Network indicators are defanged. Analyst-produced
artifacts are identified separately from files present in the original
collection. Proofpoint's
[Cruciferra report](https://www.proofpoint.com/us/blog/threat-insight/unpacking-cruciferra-analysis-sophisticated-crypter-service)
is used only to corroborate the campaign provenance of the exact 33863 outer
ZIP hash; source-only indicators are not imported.

## Network and Certificate Indicators

### Command-and-Control Endpoints

| Indicator | Role | Confidence and scope |
| --- | --- | --- |
| `103.59.103[.]93:4449` | Configured VenomRAT endpoint | Directly recovered from the locally decrypted and HMAC-validated payload configuration; runtime reachability unobserved |
| `103.97.128[.]141:4449` | Configured VenomRAT endpoint | Directly recovered from the locally decrypted and HMAC-validated payload configuration; runtime reachability unobserved |

### Pinned TLS Certificate

| Type | Value |
| --- | --- |
| SHA-256 | `da8751a11fbd4f9638aab7fbd89ba21d8e1d9661710e7d04f35268bb4e3564ef` |
| SHA-1 | `811816215363259bb445a45422e60ff5d02c18f5` |
| SPKI SHA-256 | `8c1f16f891ec0decbebf06abc4a1d4db64fe5df19c1edaf342b4a0a79ce8922d` |
| Serial | `F8D5DCAEBB74E335D238A4A8AB87EF26AA0C7FC7` |
| Subject | `CN=Venom` |
| Issuer organization | `Venom By alexeikun` |

The recovered payload pins this certificate during TLS validation. Treat it
as a sample-level pivot; the local files do not establish that the
certificate is unique to TA4922 or that either configured endpoint was
reachable during the campaign.

## File and Payload Indicators

### Reconstructed 33863 Chain

| SHA-256 | Artifact | Context |
| --- | --- | --- |
| `6dbd6f9f2fa636c16ac4fa81418b68a604424861b9650dd9c4f2b0ba6f67d6ac` | `Tax-Number33863.zip` | Exact June 1 hash published by Proofpoint |
| `7135f0b82fe9025fb8fb27db851c5ab1cd9741368ae09b5bb00d5642981a139b` | `Tax-Number33863.img` | Disk image extracted locally from the ZIP |
| `59c56c4c338d62430b54379884384ebeacfaf3c667ff7086128aa0113a80493a` | `Tax-Number33863.exe` | Legitimate Emsisoft Security Center host with an Emsisoft Limited Authenticode subject, abused for DLL side-loading |
| `ddebc8ccab9f58eb37c48937926ecd51c7973afef9dcf066afd602944a4f5a9f` | `secur32.dll` | Malicious Cruciferra DLL with large `jkhi` overlay |
| `b872a9d33cd0eb2aaca79ab2dbc4597b214463804e3d20c92eceb5f1ac5a2515` | PE-backed `secur32.dll` | Analyst-produced overlay-trimmed copy; not a delivered-file hash |

### Locally Recovered 119863 Chain — Outer ZIP Match Not Established

| SHA-256 | Artifact | Context |
| --- | --- | --- |
| `84cf4b75f6634e1637124a5c7bd0ae18b56d2e2ecce51bbf7e4a39215cfe01d6` | `Tax-Number119863.img` | Local image; no corresponding outer ZIP was present in the collection |
| `0a1fd68a1fbab226ed926977f89df6621713aac36da7ee076a30db99d8be4c5c` | `Tax-Number119863.exe` | Legitimate GoodSync Log Viewer host with a Siber Systems Authenticode subject, abused for DLL side-loading |
| `5f7e21981f76e7c1c909d92969858eff990e23ddc21071d7fe8ec1603994121d` | `Secur32.dll` | Malicious Cruciferra DLL with large `JKHI` overlay |
| `e3aea0414d3b4fff20b85b63c1659bdbb064ce097984b8202f9e92a5d87d6879` | PE-backed `Secur32.dll` | Analyst-produced overlay-trimmed copy; not a delivered-file hash |

The Authenticode descriptions above reflect embedded signature metadata
inspected offline; they are not current trust assessments. The two legitimate
host hashes should not be treated as malicious indicators in isolation.

### Recovered Objects

| SHA-256 | Object | Analytic use |
| --- | --- | --- |
| `73824a5b8fc030d0de7feaaf0c515db889a87ed3b91b5b9812cedd791f4bbf14` | 33863 decoded container | Analytical artifact produced during static extraction; not observed as a standalone delivered file |
| `fbeb3ab69d49c15b18e7c3024c5ed76d0a93442df3e62805d6d352cab73885dd` | Decrypted `Client` .NET payload | Payload-level detection and retrospective hunting |
| `07c5209bf83065fe760f4fee4ed2308b0c523671f68ca73a3854c2c8c28c0541` | Decrypted OPSWAT `ardrv.sys` | Locally recovered third-party component affected by CVE-2026-36425; actor specificity is not established by local evidence |
| `e25f410d567c3f648e0998efcbc19ac91b97713cc29490230aaf1e66b74c5fa5` | 119863 decoded container | Analytical artifact produced during static extraction; not observed as a standalone delivered file |
| `e0bef7f04afe55b8d90261f6e64a6f7874dccf9f901080bd0c540e637c80f6dc` | Extracted VenomRAT hVNC 6.0.9 assembly | Exact embedded component; actor specificity is not established by local evidence |
| `2225f4056a19536d497630afe921e85f44749259e893611a5e20d58ef0813a47` | Embedded ToggleDefender PowerShell text | SHA-256 of the analyst-produced UTF-8 rendering; capability correlation only and not a standalone actor indicator |

## Host, Loader, and Behavioral Artifacts

| Artifact | Context |
| --- | --- |
| `GetUserNameExW` | Export exposed by the malicious side-loaded DLL and invoked by both legitimate host executables; the API name alone is not discriminating |
| `SetOdgovorila` | 33863 build marker immediately before the encoded `.reloc` container |
| `ShinBijesa` | 119863 build marker immediately before the encoded `.reloc` container |
| `PQRSTUVWXYZ[\]^_` | Nibble alphabet used for the long Base16-encoded container |
| `jkhi` / `JKHI` repeated to EOF | Repeated binary-padding pattern extending to the end of the file |
| `PcaSvc_procmon` | Driver service name embedded in the 33863 loader |
| `Performance Counter DLL Host` | Driver service display name |
| `C:\Windows\System32\drivers\pcdhost.sys` | Staged vulnerable-driver path |
| `\\.\ardrv` | User-mode device path opened by the loader |
| `\Device\ardrv` | Kernel device name in the recovered driver |
| `\DosDevices\ardrv` | DOS device link in the recovered driver |
| `0x2420031` | Vulnerable process-termination IOCTL used by `ardrv.sys` |
| `VenomRATByVenom` | VenomRAT-family PBKDF2 salt; do not use alone for actor attribution |
| `fldnqpgqpzd` | Mutex observed in the recovered 33863 payload; broader campaign reuse is not established |
| `RAT + hVNC  6.0.9 Cracked By t.me/VidBckup` | Embedded payload version and banner string |
| `Wihnup.exe` in `%AppData%` | Configured installation path and filename; inactive because `Install=false` in this build |

Together, the driver artifacts define a statically implemented sequence:
create `PcaSvc_procmon`, write and load `pcdhost.sys`, open `\\.\ardrv`, and
issue IOCTL `0x2420031`. Static analysis does not establish successful
execution. Individual elements are less discriminating when observed without
the complete sequence.

## Cryptographic and Build Pivots

| Value | Meaning | Scope |
| --- | --- | --- |
| `s48HMc+v1q2wm3p6ZtUiYNqAe9XKkFeoCBwm3jQIW+OoqVA6qJjI/GxNtFyWQqlT` | Base64-encoded 48-byte outer key | Observed in the 33863 build; broader reuse is not established |
| `140d1e6cec277fa2de46b890acc361fe583c153fbdaa55da6be6f51396307102` | SHA-256 of decoded outer key | 33863 build pivot |
| `yew5kW3JeeA0VwtY64gP3vSjpGBSFBg3rd6p/PyiMRrBU1uTx68FQEf/4plE0a2A` | Base64-encoded 48-byte outer key | 119863 build pivot; materialized by NativeAOT hydration |
| `e2e0be60905e89b8936285876ed0bcc9202525686ec91888022ed3cf90585976` | SHA-256 of decoded outer key | 119863 build pivot |
| `UkZra1ZzVmVweVFxM2tIUXRJY21OZHhZQ0JPdWFsTWI=` | Base64 client configuration key | Recovered VenomRAT build/cluster pivot |
| `RFkkVsVepyQq3kHQtIcmNdxYCBOualMb` | Decoded client configuration key | Recovered VenomRAT build/cluster pivot |
| `d238ac4193c3eb84af7bf6bd9d04bd704ecf7ddccc12b596582d614ab33c7246` | SHA-256 of decoded client key | Derived non-file hash suitable for key-based correlation and reporting |
| `0x9e3779b9`, `0x6a09e667`, `0xbb67ae85` | Constants in the custom 24-round ARX transform | Useful when correlated with the P-through-underscore container encoding; insufficient in isolation |
| Rotations `16,12,8,7` | ChaCha-like quarter-round structure | Cruciferra variant signal; insufficient to establish an implementation of standard ChaCha |

The 119863 key is not present contiguously in the on-disk file. It was
recovered through static reconstruction of the loader's NativeAOT
dehydrated-data stream and becomes observable as a UTF-16LE string only
after hydration.

## Excluded Local Artifact

The collection also contains the ZIP file with SHA-256
`3f31aee0948d16f8d64bf6bec69a4331099993e502b11bfc56b2c0112024489d`.
It contains a single Windows shortcut and was not part of either analyzed
Tax-Number chain.
