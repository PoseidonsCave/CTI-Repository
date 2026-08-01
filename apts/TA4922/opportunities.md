# Investigation Opportunities

This report translates the local TA4922 sample analysis into scoping actions,
hunting opportunities, and collection priorities. Loader, Cruciferra,
VenomRAT, and vulnerable-driver signals remain separate to preserve their
respective attribution scope.

## Immediate Scoping

1. Hunt for the exact 33863 hashes and related 119863 hashes, preserving the
   original oversized DLLs as well as any overlay-trimmed analysis copies.
2. Review image-load telemetry for a non-system `Secur32.dll` beside
   `Tax-Number33863.exe`, `Tax-Number119863.exe`, `a2start.exe`, or
   `LogView.exe`.
3. Prioritize systems with service `PcaSvc_procmon`, driver filename
   `pcdhost.sys`, device `\\.\ardrv`, or the exact recovered driver hash.
4. Search endpoint network telemetry for `103.59.103[.]93:4449` and
   `103.97.128[.]141:4449`.
5. Pivot on certificate SHA-1
   `811816215363259bb445a45422e60ff5d02c18f5`, but require payload,
   endpoint, or configured-address corroboration before assigning TA4922
   relevance.

## Endpoint Hunting

### Packaging and DLL Side-Loading

Hunt for:

- archives or disk images matching the local `Tax-Number*` naming pattern and
  containing a host executable with an embedded Authenticode signature and
  an adjacent case-insensitive `Secur32.dll`;
- `Tax-Number*.exe` loading `Secur32.dll` from its working directory rather
  than from `System32` or `SysWOW64`;
- the Emsisoft Security Center or GoodSync Log Viewer host, with the observed
  Authenticode subject, appearing in user, temporary, mounted-image, or
  archive-extraction paths;
- creation of a 331–379 MB DLL whose executable PE content
  occupies only about 8 MB and whose tail repeats `jkhi` or `JKHI`; and
- a malicious DLL exporting `GetUserNameExW` while carrying an oversized
  `.reloc` section.

The host binaries are legitimate software. Their filenames, products, and
signers are insufficient as standalone malicious indicators; correlate them
with the adjacent DLL, path, hash, or execution-chain context.

### Cruciferra Structural Signals

For file hunting and sample triage, combine multiple traits:

- a long `.reloc` run restricted to bytes `0x50`–`0x5f`;
- decoded prefix `02 00 00 00`, represented as `PRPPPPPP` in the encoded
  stream;
- build marker `SetOdgovorila` or `ShinBijesa`;
- ARX constants `0x9e3779b9`, `0x6a09e667`, and `0xbb67ae85`;
- rotations `16/12/8/7`, 24 schedule-word rounds, and a 16-byte block;
- exported `GetUserNameExW`; and
- a terminal lowercase or uppercase `jkhi` overlay.

The constants and rotations resemble ChaCha but lack sufficient specificity
as standalone indicators. Use the multi-trait YARA rule in
`detection_scripts/ta4922_static.yar` as the primary starting point.

### Process Construction and UAC

Where EDR or ETW exposes the necessary events, investigate:

- temporary PE writes followed by `NtCreateSection` with `SEC_IMAGE`, a
  subsequent delete-disposition request, and suspended process construction;
- a newly created process whose image backing file was delete-pending before
  the first thread resumed;
- an anomalous parent with an embedded Authenticode signature creating or
  manipulating `jsc.exe` or `notepad.exe`;
- COM elevation activity using CLSID
  `{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` with an
  `Elevation:Administrator!new:` moniker.

Process Ghosting is **Locally confirmed** as implemented only in the related
119863 image. Runtime use was not observed, and no victim telemetry was
available.

### BYOVD and Defense Impairment

Correlate these events as one high-priority sequence:

1. write `C:\Windows\System32\drivers\pcdhost.sys`;
2. create and start kernel service `PcaSvc_procmon`;
3. open `\\.\ardrv`;
4. enumerate security-product processes; and
5. issue `DeviceIoControl` request `0x2420031` with a PID input buffer.

The driver is a legitimate, vulnerable OPSWAT AppRemover component. Its
presence without the loader, service, and process-termination sequence is
insufficient for TA4922 attribution. See `cves.md` for the vulnerability
boundary.

## Network Hunting

### Configured C2

- Correlate outbound TCP/4449 with either locally configured address and the
  pinned certificate.
- If TLS metadata is retained, search certificate SHA-1, SHA-256, serial,
  subject `CN=Venom`, and SPKI SHA-256 from `iocs.md`.
- If authorized TLS decryption or endpoint plaintext telemetry is available,
  look for four-byte little-endian record lengths followed by MessagePack and
  framed `PING` keepalives.

The addresses, port, and certificate are recovered configuration artifacts.
Static analysis does not establish successful communication or current
endpoint availability.

## Static Analysis Workflow

- Run `code/extract_cruciferra.py` without a key to inventory markers,
  container hashes, entry names, lengths, and ciphertext hashes without
  loading the sample.
- For a new variant, search the loader's referenced string objects and key
  construction call graph for a 64-character Base64 value that decodes to 48
  bytes.
- If the key object falls in virtual-only `.data`, inspect the ReadyToRun
  `FrozenObjectRegion` and `DehydratedData` section. The
  `code/rehydrate_nativeaot.py` parser recovers the 119863 key without
  executing the NativeAOT initializer.
- Compare the custom key schedule and block construction with
  `code/cruciferra_arx_reference.c`. A match identifies the custom ARX
  implementation, not standard ChaCha.
- Pivot on the decoded 33863 outer-key SHA-256 instead of broadly searching
  for the raw key in systems where access to potential secret values is
  restricted.
- The recovered 119863 key decrypts both entries to exact hash matches with
  the 33863 payload and driver; use that equality as a cross-variant pivot.
- Hunt managed assemblies for the paired `VenomRATByVenom` salt and embedded
  Base64 configuration key. Require the paired values or additional local
  sample structure before assigning TA4922 relevance.
- Hunt for the recovered protocol typos (`Pac_ket`, `SEND_MOMORY`,
  `CLINENETSTATT_INFO`) with plugin namespaces, and for the
  StormKitty-referencing CDP/DPAPI/NSS browser-recovery cluster.
- Carve `Client.Properties.Resources` during triage. This build contains an
  exact hVNC 6.0.9 component and a ToggleDefender PowerShell resource that
  provide additional detection coverage.

## Collection Priorities

1. Locally acquired archive, disk image, and full padded DLL, with timestamps
   and hashes preserved.
2. Host with an embedded Authenticode signature, adjacent DLL, mounted-image
   metadata, Prefetch, Amcache, Shimcache, LNK, and archive-extraction
   artifacts.
3. Sysmon or EDR image loads, process trees, file operations, service events,
   driver loads, device opens, and process-access telemetry.
4. The full `PcaSvc_procmon` registry/service configuration and a forensic copy
   of `pcdhost.sys`.
5. DNS, flow, TLS handshake, certificate, and endpoint socket telemetry for
   TCP/4449.
6. Collect process memory only from an already affected endpoint and under
   established incident-response authority. It may contain
   runtime-materialized keys or decrypted configuration.

## Controlled Follow-Up

- Static reconstruction recovered the 119863 outer key. Any dynamic analysis
  would therefore be limited to validating tasking, successful injection,
  decrypted live protocol records, and volatile session state.
- Validate the Suricata rule with the target production engine and convert the
  Sigma rules through the organization's selected backend.
- Validate Authenticode chains and revocation status in a non-sample-facing
  workflow before relying on signer state operationally.

## Attribution Guardrails

- **Source-reported / Locally confirmed:** The local 33863 archive exactly
  matches Proofpoint's published TA4922 hash.
- **Locally confirmed:** The related 119863 image has a close technical
  relationship to the 33863 chain, but no corresponding outer ZIP is present
  locally and independent TA4922 attribution is not established.
- **Locally confirmed:** Custom Cruciferra traits constitute crypter-family
  or close-variant evidence.
- **Capability only:** VenomRAT features constitute payload-family capability
  evidence, not evidence of operator use.
- **Locally confirmed:** The embedded certificate is a sample-linked
  configuration pivot; it does not independently establish infrastructure
  ownership or successful communication.
- **Locally confirmed:** `ardrv.sys` constitutes vulnerable-component
  evidence; local evidence does not establish actor specificity.
