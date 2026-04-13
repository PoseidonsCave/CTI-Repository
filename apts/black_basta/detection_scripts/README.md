# Black Basta Detection Pack

This folder contains starting-point detection content derived from the broader Black Basta source material spanning September 2023 through September 2024.

## Coverage

- XLL-driven execution chains from Excel into script hosts or installers
- Enterprise VPN discovery through `reg query`
- Credential dumping at scale via `proxychains` and `secretsdump.py`
- Network contact with repeated Black Basta delivery infrastructure such as `temp.sh` and `qaz.im`
- ESXi locker preparation and execution command lines
- Rubeus Kerberoast collection into hashcat-formatted output files
- Network contact with later `backconnect`, `ghostsocks`, and `rdweb-page` infrastructure

## Files

- [bb_excel_xll_child_process.yml](bb_excel_xll_child_process.yml)
- [bb_vpn_registry_enumeration.yml](bb_vpn_registry_enumeration.yml)
- [bb_proxychains_secretsdump.yml](bb_proxychains_secretsdump.yml)
- [bb_staging_domain_contact.yml](bb_staging_domain_contact.yml)
- [bb_esxi_locker_commands.yml](bb_esxi_locker_commands.yml)
- [bb_rubeus_kerberoast.yml](bb_rubeus_kerberoast.yml)
- [bb_backconnect_rdweb_domains.yml](bb_backconnect_rdweb_domains.yml)

## Implementation Notes

- These Sigma rules are intentionally narrow and map to behaviors directly visible in the leak.
- Some environments will need field remapping for process creation, network connection, or proxy data.
- The network-focused rules are best deployed in EDR network telemetry, proxy logs, or DNS analytics with equivalent fields.
- The ESXi rule uses generic Linux process telemetry because Sigma does not have a universal ESXi logsource profile.