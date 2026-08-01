# Native and Managed Code Analysis

## C-Like Decompilation

Both overlay-trimmed DLLs were imported into Ghidra as PE32+ x86-64 images.
An analyst-authored script exported entry-point and call-graph closures as
C-like `.c` files. These files are reconstructions rather than original
source. Names such as `FUN_18000d160` are retained where symbol intent could
not be established.

Analytically significant 33863 functions:

| VA | C-like role | Evidence |
| --- | --- | --- |
| `0x180007780` | Main feature gate | Consumes `edr_killer;startup;uac_bypass;disable_user_notification;hide_console` |
| `0x1800019a0` | Outer key expansion | Expands eight key words to 24 with rotate/XOR/add and `0x9e3779b9` |
| `0x180001a40` | Outer stream transform | Generates 16-byte counter blocks with 24 ARX rounds |
| `0x180002190` | UAC elevation path | Builds the CMSTPLUA-style COM Elevation Moniker |
| `0x180008b20` | Security-process target construction | Consumes 138 AV/EDR process-name strings |
| `0x18000d020` | Driver IOCTL getter | `mov eax, 0x2420031; ret` |
| `0x18000d160` | Driver deployment/open path | Stages `pcdhost.sys`, creates/starts `PcaSvc_procmon`, opens `\\.\ardrv` |
| `0x18000de60` | Security-process sweep | Passes PID buffers and IOCTL `0x2420031` to resolved `DeviceIoControl` |
| `0x18000ec30` | API resolver | Decrypts/resolves `DeviceIoControl` and stores the function pointer |

Analytically significant 119863 functions:

| VA | C-like role | Evidence |
| --- | --- | --- |
| `0x18005b2a0` | Reachable outer entry closure | Root used to build the C-like analysis set |
| `0x180055080` | Outer key expansion | Same 24-word schedule as the 33863 implementation |
| `0x180055120` | Outer stream transform | Reads the hydrated key object at `0x180172478` |
| `0x18005ecb0` | Process Ghosting backing-file core | Writes payload, creates `SEC_IMAGE`, then sets delete disposition |
| `0x18005e4e0` | Ghosting caller/coordination | Links the backing-file section to subsequent process/thread construction helpers |
| `0x180036660` | NativeAOT data rehydration | Reconstructs frozen objects from type-207 dehydrated data before managed initialization |

## DLL Side-Loading

Each disk image contains a legitimate executable with embedded Authenticode
signature metadata beside a malicious DLL named `Secur32.dll` or
`secur32.dll`. The host resolves the export `GetUserNameExW`, transferring
execution into Cruciferra within the legitimate host process. This execution
path directly establishes DLL side-loading rather than relying solely on
filenames.

The original malicious DLLs are 331–379 MB, but the PE-backed images are
approximately 8 MB. The difference consists of a uniform, repeating overlay:

- 33863: lowercase `jkhijkhi...`
- 119863: uppercase `JKHIJKHI...`

This binary padding can impede collection and scanning. The overlay is not
required for structural decompilation.

## Outer Loader Configuration and Strings

The 33863 loader applies its custom ARX routine to both payload objects and
individual string objects. Offline reconstruction recovered all 226 referenced
strings without error.

Analytically relevant strings:

```text
edr_killer;startup;uac_bypass;disable_user_notification;hide_console
\\.\ardrv
C:\Windows\System32\drivers\pcdhost.sys
PcaSvc_procmon
Performance Counter DLL Host
Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}
C:\Windows\Microsoft.NET\Framework\v4.0.30319\jsc.exe
notepad.exe
UAC: sleep done — continuing to hollowing
Could not apply PEB masquerade
```

The target list covers 138 security-product process names, including
Microsoft Defender, CrowdStrike, SentinelOne, Elastic, Sophos, Cylance,
Cybereason, Fortinet, Malwarebytes, Avast, Kaspersky, ESET, McAfee,
Symantec, Bitdefender, Avira, Trend Micro, and Webroot. Individual vendor
process names are not TA4922 indicators. The list's breadth and its use by the
loader constitute behavioral evidence.

## Statically Confirmed Driver Invocation Path

The following data flow establishes the BYOVD path throughout the observed
call chain:

1. `FUN_18000d160` writes the recovered driver to
   `C:\Windows\System32\drivers\pcdhost.sys`.
2. It installs and starts service `PcaSvc_procmon`, then attempts to open
   `\\.\ardrv` up to ten times.
3. `FUN_18000ec30` decrypts and resolves `DeviceIoControl`, storing the
   pointer at sweep-object offset `+0x58`.
4. `FUN_18000de60` calls the getter at `0x18000d020`.
5. The getter returns `0x2420031`; the caller moves it into the second
   Windows x64 argument register.
6. The resolved API is invoked with the driver handle and a PID input
   buffer.

The bundled driver recognizes several IOCTLs. The statically established
loader call uses `0x2420031`, the process-termination path documented by
[CVE-2026-36425](https://nvd.nist.gov/vuln/detail/CVE-2026-36425).

## Process Ghosting

The 119863 C-like decompilation set provides static evidence of the
implemented Process Ghosting technique:

- create or open a temporary backing file;
- write the payload bytes;
- create a section with `SEC_IMAGE`;
- set file-information class 13 with the delete flag;
- close the file while retaining the image section;
- construct a process and thread around the section.

The 33863 string set additionally names `jsc.exe` as the primary hollowing
target and `notepad.exe` as a fallback. Because no sample was executed, this
evidence establishes the implemented logic and configured paths but does not
establish successful execution on a victim system.

## NativeAOT Frozen-Key Reconstruction

Unlike 33863, the 119863 outer key object is not file-backed. Its address is
inside the ReadyToRun `FrozenObjectRegion` and is produced by the
`DehydratedData` startup stream. Disassembly of the embedded runtime
rehydration function established the exact six-command grammar, and the
offline parser in `rehydrate_nativeaot.py` reconstructed the object without
calling any initializer.

The recovered Base64 key decodes to 48 bytes and successfully decrypts both
119863 container entries. Their complete hashes and sizes exactly match the
managed client and `ardrv.sys` from 33863. This result independently confirms
the prior known-plaintext hypothesis and demonstrates that the two loader
variants package the same inner objects behind different outer keys.

## Decrypted Managed Client

The primary object is a PE32 CIL assembly:

| Field | Value |
| --- | --- |
| Assembly | `Client` |
| Version | `6.0.9.0` |
| SHA-256 | `fbeb3ab69d49c15b18e7c3024c5ed76d0a93442df3e62805d6d352cab73885dd` |
| Type-definition rows | 2,702 |
| Manifest resources | 17 |

Static IL decompilation identified `Client.Settings`,
`Client.Algorithm.Aes256`, `Client.Connection.Connection`, and
`Client.Helper.DInvokeCore`. The salt `VenomRATByVenom`, the `CN=Venom`
certificate, and the banner `RAT + hVNC  6.0.9` support a
VenomRAT-derived classification.

The client includes service, process, file, registry, netstat, reverse-proxy,
remote-desktop, camera, audio, keylogger, browser-recovery, transfer, and
in-memory execution code. These features represent bundled capabilities. Only
configuration bootstrap and connection construction are characterized as
configured behavior.

## Limits

- Static analysis does not establish runtime success, current C2
  availability, or which RAT commands an operator issued.
- Future-dated PE timestamps are not timeline evidence.
- Decompiled variable names and inferred types may be inaccurate even when the
  surrounding data flow is clear.
