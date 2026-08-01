# Detection Scripts

This directory contains defensive detection content derived from static,
offline analysis of the Proofpoint-hash-corroborated 33863 chain and the
technically related local 119863 Cruciferra image. The inner payload and
driver are byte-identical across both builds. The 119863 image is not
independently attributed to TA4922. These rules were developed and validated
without executing any sample.

## Coverage and Confidence

- `ta4922_static.yar`
  - A medium-confidence Cruciferra family or close-variant rule combines the
    `GetUserNameExW` side-load export, an oversized `.reloc` section, the
    P-through-underscore encoded two-entry container prefix, all three custom
    ARX constants, one build marker, and the lower- or uppercase `jkhi` overlay
    tail.
  - High-confidence exact-file rules identify both malicious `Secur32.dll`
    files, the decrypted VenomRAT-derived payload, and the decrypted
    `ardrv.sys`.
  - The static VenomRAT cluster rule combines `VenomRATByVenom` with the
    build-specific Base64 configuration key.
  - Capability-cluster rules cover the managed plugin/protocol surface,
    StormKitty-referencing CDP/DPAPI/NSS browser recovery, the embedded
    ToggleDefender resource, and the carved hVNC 6.0.9 component.
  - A build-key rule pairs each exact outer key with its corresponding
    Cruciferra marker. The 119863 key is expected only after NativeAOT
    hydration or within reconstructed data or process memory.
  - An exact-component rule covers the 38,912-byte hVNC assembly carved from
    `Client.Properties.Resources`.
  - The version-banner rule applies to process memory or analyst-decrypted
    configuration. Because the banner is encrypted in the on-disk payload, the
    rule is not expected to match that file directly.
  - A component-level `ardrv` rule identifies the OPSWAT AppRemover driver by
    product version and device names. This is a legitimate but vulnerable
    driver, and its identification does not imply TA4922 attribution.
- `cruciferra_local_sideload_image_load.yml` detects the two observed
  executable/DLL side-load pairs while excluding normal Windows copies, plus
  exact malicious DLL hashes.
- `ta4922_ardrv_service_install.yml` detects the observed
  `PcaSvc_procmon`/`pcdhost.sys` service-install chain.
- `ardrv_exact_driver_load.yml` detects the exact embedded driver hash.
- `cruciferra_pcdhost_driver_name_hunt.yml` provides a separate
  medium-confidence hunt for the observed renamed filename; it does not
  establish driver identity.
- `ta4922_venomrat_c2.yml` detects the two decrypted IP addresses on TCP/4449.
- `venomrat_cdp_cookie_access.yml` is a medium-confidence process hunt
  for Chrome or Edge launched headless on fixed DevTools port 9222 with the
  exact flag combination used by the cookie-recovery module.
- `venomrat_toggledefender_script.yml` detects the five-string
  ToggleDefender cluster in PowerShell script-block telemetry.
- `venomrat_pinned_certificate.rules` matches the pinned TLS server-certificate
  SHA-1 fingerprint.

## Attribution Boundaries

The Cruciferra DLL traits and exact-file rules identify artifacts in the local
sample set. Attribution depends on separately established sample provenance;
an exact hash considered without that context is not independently sufficient
for TA4922 attribution. The locally decrypted payload is VenomRAT-derived, and
the locally recovered `ardrv` file is a legitimate but vulnerable driver.
Local evidence does not establish actor specificity for either component.

The pinned certificate was recovered from the local client configuration. It
can support **VenomRAT-family** hunting when correlated with other local sample
traits, but the local evidence does not establish that it is unique to
TA4922. Its recovered values are:

- Certificate SHA-1:
  `811816215363259bb445a45422e60ff5d02c18f5`
- Certificate SHA-256:
  `da8751a11fbd4f9638aab7fbd89ba21d8e1d9661710e7d04f35268bb4e3564ef`
- Subject public-key-info SHA-256:
  `8c1f16f891ec0decbebf06abc4a1d4db64fe5df19c1edaf342b4a0a79ce8922d`

The IP indicators and Base64 configuration key were recovered from the local
decrypted configuration. Treat them as configuration-level signals that can
become stale. For hunting, prioritize the multi-trait YARA rule and correlate
results with the certificate, execution-chain, endpoint, and sample-provenance
context before assigning campaign attribution.

## Deployment Notes

- Tune the Sigma field mapping for the deployed EDR/Sysmon pipeline. In
  particular, Windows Event ID 7045 providers may expose the driver path as
  either `ImagePath` or `ServiceFileName`.
- Enable Sysmon image-load telemetry for the relevant applications before
  deploying the side-load rule.
- Treat the `pcdhost.sys` name-only driver condition as a medium-confidence
  hunting condition until it is correlated with signer, version, hash,
  service, or process context.
- Expect legitimate browser automation to overlap the CDP process rule.
  Prioritize unknown parent processes, user-session anomalies, browser
  termination immediately before relaunch, and subsequent localhost
  DevTools/WebSocket activity.
- Suricata must inspect TLS handshakes to populate `tls.cert_fingerprint`.
  Encrypted or incomplete sessions, sensor placement, and TLS parser limits can
  prevent the certificate rule from firing.
- Rules are Apache-2.0 licensed; see `LICENSE`.

## Validation

Validation was performed in a network-disabled REMnux container with samples
mounted read-only. No Windows sample was loaded or executed.

Validated on 2026-07-30 with YARA 4.5.0:

- `yarac ta4922_static.yar`: compiled successfully.
- Tax-Number33863 `secur32.dll`: matched the medium-confidence Cruciferra
  static rule, the 33863 exact-build rule, and the paired build-key rule.
- Tax-Number119863 `Secur32.dll`: matched the medium-confidence Cruciferra
  static rule and the 119863 exact-build rule. Its key rule is memory-oriented
  because the UTF-16 key is reconstructed into virtual-only data.
- Decrypted VenomRAT-derived payload: matched the static payload-cluster rule
  and payload exact-build rule, plus all four managed capability-cluster
  rules. The identical payload recovered from 119863 matched the same set of
  rules.
- Carved hVNC resource: matched the hVNC component and exact-component rules.
- Decrypted ardrv driver: matched the exact embedded-driver rule and
  component-identification rule only.
- Analyst-decrypted VenomRAT JSON configuration: matched the decrypted
  version-banner rule only.
- Both legitimate side-load host executables and the unrelated local
  `3f31aee0...` file produced no YARA matches. The original outer ZIP also
  produced no matches.
