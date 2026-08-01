# Overview

## Executive Summary

The local sample set contains `Tax-Number33863.zip`, which matches the
SHA-256 that
[Proofpoint published for TA4922](https://www.proofpoint.com/us/blog/threat-insight/unpacking-cruciferra-analysis-sophisticated-crypter-service),
and a technically related `Tax-Number119863.img` for which no outer ZIP is
present locally. This distinction anchors the 33863 chain directly while
retaining the 119863 image as a related local artifact whose attribution is
not independently established.

Static analysis recovered a custom `P`-through-`_` Base16 container, a
nonstandard ChaCha-like ARX stream transform, a VenomRAT-derived managed
payload, and a vulnerable OPSWAT `ardrv.sys` driver. Both loader variants
decrypt to byte-for-byte identical copies of the managed payload and driver.
The RAT configuration specifies two C2 addresses on TCP/4449 and pins an
embedded certificate.

This dossier classifies the recovered payload as **VenomRAT-derived** based
on the locally recovered strings `VenomRATByVenom`, `CN=Venom`, and
`RAT + hVNC 6.0.9`. Proofpoint identifies the payload in the hash-matched
33863 chain as AsyncRAT; that source label is retained as provenance rather
than treated as an additional local finding.

## Recovered Component Chain

```text
local ZIP or disk image
  -> host EXE with embedded Authenticode signature + adjacent Secur32.dll
  -> DLL side-loading through GetUserNameExW
  -> P–_ Base16 container in .reloc
  -> custom 24-round ARX decryption
  -> VenomRAT-derived client + vulnerable ardrv.sys
  -> configured certificate-pinned TLS over raw TCP/4449
```

This chain represents static relationships recovered from the local files.
It does not establish successful execution on a victim system or a
connection to either configured C2 address.

## Locally Confirmed Findings

### Packaging and Side-Loading

- The locally analyzed `Tax-Number33863.zip` exactly matches the
  Proofpoint-listed archive.
- Its disk image contains an Emsisoft Security Center host (`a2start.exe`)
  with an embedded Authenticode signature naming Emsisoft Limited, together
  with malicious `secur32.dll`.
- The separate `Tax-Number119863.img` contains a GoodSync Log Viewer
  (`LogView.exe`) with an embedded Authenticode signature naming Siber
  Systems, together with malicious `Secur32.dll`. No corresponding outer ZIP
  is present locally, so the image is classified as a related local artifact
  rather than an independently attributed TA4922 chain.
- Both hosts resolve the malicious export `GetUserNameExW`.
- The DLLs are padded to hundreds of megabytes with repeated `jkhi` or
  `JKHI` overlay data.

### Cruciferra Layer

- Both variants place an encoded two-entry container in `.reloc`.
- Bytes `P` through `_` represent nibbles `0` through `15`.
- Container grammar is a little-endian entry count followed by a 7-bit
  UTF-8 name length, name, little-endian value length, and value.
- Both implement the same 16-byte stream transform with rotations
  `16/12/8/7`, 24 rounds, and constants `0x9e3779b9`, `0x6a09e667`, and
  `0xbb67ae85`.
- This construction resembles a ChaCha quarter round but is **not standard
  ChaCha**. Its key is therefore described as a custom ARX key, not a
  “ChaCha key.”
- The 33863 build stores its fixed 48-byte key in file-backed data. The
  119863 build materializes a different 48-byte key through the .NET
  NativeAOT dehydrated-data stream.
- Offline reconstruction recovered the second key and decrypted both 119863
  entries. The managed payload and `ardrv.sys` are byte-for-byte identical to
  their 33863 counterparts.

### Payload and Driver

- The decrypted primary object is a 32-bit .NET assembly named `Client`,
  version `6.0.9.0`; the same object is packaged in both local loader variants.
- Its configuration specifies
  `103.59.103[.]93,103.97.128[.]141` on TCP/4449.
- Communications use raw TCP wrapped in `SslStream`, certificate pinning,
  a four-byte little-endian length prefix, and MessagePack records.
- The RAT's settings are authenticated with HMAC-SHA256 and encrypted with
  AES-256-CBC after PBKDF2-HMAC-SHA1 key derivation.
- Managed resources include an exact 38,912-byte hVNC 6.0.9 assembly and a
  ToggleDefender PowerShell script. The browser-recovery module includes
  DPAPI, Firefox NSS, and Chrome/Edge DevTools cookie collection paths.
- The second decrypted object is the legitimate, vulnerable OPSWAT
  AppRemover driver `ardrv.sys`, version `2017.10.02.1551`.
- The loader opens `\\.\ardrv`, stages the driver as
  `C:\Windows\System32\drivers\pcdhost.sys`, creates service
  `PcaSvc_procmon`, and contains the exact vulnerable IOCTL `0x2420031`.
- [CVE-2026-36425](https://nvd.nist.gov/vuln/detail/CVE-2026-36425)
  documents the affected driver version and IOCTL. The NVD references include
  the exact recovered SHA-256.
