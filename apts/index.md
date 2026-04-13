# APT Dossiers

## Black Basta

Black Basta has a completed dossier based on source material spanning September 2023 through September 2024. It is written to support both CTI analysis and hands-on investigation. The strongest evidence covers early setup activity, COBA and Cobalt Strike infrastructure, payload delivery, remote-access validation, SOCKS infrastructure, ESXi encryption activity, and later decryptor troubleshooting.

### Core Intelligence

- [apts/black_basta/infrastructure.md](apts/black_basta/infrastructure.md)
- [apts/black_basta/iocs.md](apts/black_basta/iocs.md)
- [apts/black_basta/opportunities.md](apts/black_basta/opportunities.md)
- [apts/black_basta/timeline.md](apts/black_basta/timeline.md)
- [apts/black_basta/ttps.md](apts/black_basta/ttps.md)
- [apts/black_basta/cves.md](apts/black_basta/cves.md)

### Detection Content

- [apts/black_basta/detection_scripts/README.md](apts/black_basta/detection_scripts/README.md)
- [apts/black_basta/detection_scripts/bb_excel_xll_child_process.yml](apts/black_basta/detection_scripts/bb_excel_xll_child_process.yml)
- [apts/black_basta/detection_scripts/bb_vpn_registry_enumeration.yml](apts/black_basta/detection_scripts/bb_vpn_registry_enumeration.yml)
- [apts/black_basta/detection_scripts/bb_proxychains_secretsdump.yml](apts/black_basta/detection_scripts/bb_proxychains_secretsdump.yml)
- [apts/black_basta/detection_scripts/bb_staging_domain_contact.yml](apts/black_basta/detection_scripts/bb_staging_domain_contact.yml)
- [apts/black_basta/detection_scripts/bb_esxi_locker_commands.yml](apts/black_basta/detection_scripts/bb_esxi_locker_commands.yml)
- [apts/black_basta/detection_scripts/bb_rubeus_kerberoast.yml](apts/black_basta/detection_scripts/bb_rubeus_kerberoast.yml)
- [apts/black_basta/detection_scripts/bb_backconnect_rdweb_domains.yml](apts/black_basta/detection_scripts/bb_backconnect_rdweb_domains.yml)

## Notes

- Indicators are defanged where practical.
- Detection content is intended as a starting point and will require backend-specific field mapping.
- The Black Basta CVE file lists likely edge-device exploitation paths relevant to the observed infrastructure families and timeframe. These CVEs are review priorities, not direct proof of exploitation in the logs.
