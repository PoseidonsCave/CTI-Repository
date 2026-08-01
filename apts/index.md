# Threat Actor Dossiers

## TA4922

The TA4922 dossier documents offline static analysis of one
Proofpoint-hash-corroborated Cruciferra chain and one technically related
local image. Its scope is limited to collected artifacts, statically
recovered configuration and behavior, analyst-derived objects, and detection
content built from those findings. External reporting is used only for
provenance or technical corroboration.

### Core Intelligence

- [apts/TA4922/overview.md](TA4922/overview.md)
- [apts/TA4922/infrastructure.md](TA4922/infrastructure.md)
- [apts/TA4922/iocs.md](TA4922/iocs.md)
- [apts/TA4922/opportunities.md](TA4922/opportunities.md)
- [apts/TA4922/cves.md](TA4922/cves.md)
- [apts/TA4922/ttps.md](TA4922/ttps.md)

### Technical Analysis and Detection

- [apts/TA4922/code/README.md](TA4922/code/README.md)
- [apts/TA4922/detection_scripts/README.md](TA4922/detection_scripts/README.md)

## Black Basta

Black Basta has a completed dossier based on source material spanning
September 2023 through September 2024. It supports both CTI analysis and
hands-on investigation. The strongest evidence covers early setup activity,
COBA and Cobalt Strike infrastructure, payload delivery, remote-access
validation, SOCKS infrastructure, ESXi encryption activity, and later
decryptor troubleshooting.

### Core Intelligence

- [apts/black_basta/infrastructure.md](black_basta/infrastructure.md)
- [apts/black_basta/iocs.md](black_basta/iocs.md)
- [apts/black_basta/opportunities.md](black_basta/opportunities.md)
- [apts/black_basta/timeline.md](black_basta/timeline.md)
- [apts/black_basta/ttps.md](black_basta/ttps.md)
- [apts/black_basta/cves.md](black_basta/cves.md)

### Detection Content

- [apts/black_basta/detection_scripts/README.md](black_basta/detection_scripts/README.md)
- [apts/black_basta/detection_scripts/bb_excel_xll_child_process.yml](black_basta/detection_scripts/bb_excel_xll_child_process.yml)
- [apts/black_basta/detection_scripts/bb_vpn_registry_enumeration.yml](black_basta/detection_scripts/bb_vpn_registry_enumeration.yml)
- [apts/black_basta/detection_scripts/bb_proxychains_secretsdump.yml](black_basta/detection_scripts/bb_proxychains_secretsdump.yml)
- [apts/black_basta/detection_scripts/bb_staging_domain_contact.yml](black_basta/detection_scripts/bb_staging_domain_contact.yml)
- [apts/black_basta/detection_scripts/bb_esxi_locker_commands.yml](black_basta/detection_scripts/bb_esxi_locker_commands.yml)
- [apts/black_basta/detection_scripts/bb_rubeus_kerberoast.yml](black_basta/detection_scripts/bb_rubeus_kerberoast.yml)
- [apts/black_basta/detection_scripts/bb_backconnect_rdweb_domains.yml](black_basta/detection_scripts/bb_backconnect_rdweb_domains.yml)

## Notes

- Indicators are defanged where practical.
- Detection content is intended as a starting point and requires
  backend-specific field mapping.
- The Black Basta CVE file lists likely edge-device exploitation paths
  relevant to the observed infrastructure families and timeframe. These CVEs
  are review priorities, not direct proof of exploitation in the logs.
- Sample-analysis dossiers distinguish collected files, analyst-derived
  artifacts, corroborating external references, static implementation, and
  unobserved runtime behavior.
