# CVE Relevance

One vulnerability is directly relevant to this case. The vulnerable
component, version, device, and IOCTL are present in locally recovered code.
Static analysis confirms the implementation path; it does not establish
successful execution on a victim system.

## CVE-2026-36425

| Field | Local result |
| --- | --- |
| Component | OPSWAT AppRemover driver `ardrv.sys` |
| Product version | `2017.10.02.1551` |
| Recovered SHA-256 | `07c5209bf83065fe760f4fee4ed2308b0c523671f68ca73a3854c2c8c28c0541` |
| Device | `\\.\ardrv` |
| Vulnerable IOCTL | `0x2420031` |
| Local loader filename | `C:\Windows\System32\drivers\pcdhost.sys` |
| Local service | `PcaSvc_procmon` |
| Evidence state | Locally confirmed: end-to-end implementation/code path; runtime success unobserved |

The [NVD record](https://nvd.nist.gov/vuln/detail/CVE-2026-36425)
describes improper privilege validation in `ardrv.sys` version
`2017.10.02.1551` and earlier: a local user can submit process-termination
requests through IOCTL `0x2420031`. NVD's references include the exact local
driver hash. The
[research advisory](https://github.com/redteamfortress/CVE-2026-36425)
also lists that SHA-256 among affected driver variants.

## Local Code-to-CVE Link

The 33863 Cruciferra loader:

1. decrypts the exact vulnerable driver from its two-entry container;
2. writes it as `pcdhost.sys`;
3. creates and starts `PcaSvc_procmon`;
4. repeatedly attempts to open `\\.\ardrv`;
5. resolves `DeviceIoControl`;
6. obtains the literal request value `0x2420031`; and
7. invokes the resolved API with the driver handle and selected PID buffer.

Together, these observations establish the implemented defense-impairment
data flow in code, beyond a driver-string or hash match in isolation. Because
the sample was not executed and no victim telemetry was available, the
analysis does not establish that the driver loaded successfully or terminated
a process on a victim system.

## Defensive Review

- Hunt for the exact hash and correlate the service name, on-disk rename,
  device path, process discovery, and IOCTL use.
- Review code-integrity, driver-load, service-install, and EDR telemetry for
  the sequence documented in `opportunities.md`.
- Assess application-control and vulnerable-driver policy coverage for the
  recovered hash, including other organization-approved blocking mechanisms.
- If found, preserve the driver and loader before containment so signer,
  version, service, and parent-process evidence remain available.
- Treat a standalone `ardrv.sys` finding as vulnerable-component evidence,
  not TA4922 attribution. It is a third-party component, and hash presence
  alone does not establish actor attribution.
