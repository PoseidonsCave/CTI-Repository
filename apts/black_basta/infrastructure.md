# Black Basta Infrastructure

This document summarizes infrastructure directly observed in the Black Basta source material. The clearest timestamped coverage runs from September 2023 through September 2024, with a small number of later artifact references. Indicators are defanged, and working credentials are intentionally omitted.

## Scope

- Primary uses: clustering related infrastructure, supporting hunts, informing blocklists, helping with retrospective review, and generating new leads.
- Confidence: medium to high for nodes explicitly described in the logs as proxies, command-and-control systems, teamservers, staging hosts, RDP systems, VPN nodes, delivery infrastructure, SOCKS infrastructure, or validation infrastructure.
- Caveat: some nodes were short-lived test systems and may no longer be active.

## High-Confidence Infrastructure Clusters

| Indicator | Role | Observed Use | First Seen |
| --- | --- | --- | --- |
| `matrix[.]bestflowers247[.]online` | Actor communications | Matrix homeserver used by multiple operators in the leaked chats | 2023-09-18 |
| `matrixtcFJHPDblmt2rg[.]network` | Secondary communications | Additional Matrix infrastructure used in parallel with the main server | 2023-09-21 |
| `orders44vz5yl7y6xajzxsdo2n6niaqu73ty4tx6ncwqnc752yzae4ad[.]onion` | Hosting test | Cobalt Strike hosting test site referenced by operators | 2023-09-19 |
| `stniiomyjliimcgkvdszvgen3eaaoz55hreqqx6o77yvmpwt7gklffqd[.]onion` | Leak blog | Onion blog referenced as reachable while panel access was unavailable | 2023-09-19 |
| `bpeln2aqs66qqfuex2cvcyjiy5ggcwbyh5nbmxzxt6daamkmpmufv4qd[.]onion` | Admin panel | Separate onion admin panel for the same leak platform | 2023-09-19 |
| `88.214.26[.]33` / `betshopkipstri[.]com` | Cobalt Strike proxy | Explicitly described as a proxy server for Cobalt Strike | 2023-09-19 |
| `147.78.47[.]48` | Cobalt Strike teamserver | Dedicated server for Cobalt Strike operations | 2023-09-19 |
| `179.60.149[.]235` | VPN node | Shared as `Meta_US`; likely operator ingress or relay infrastructure | 2023-09-19 |
| `88.214.25[.]244` | VPN node | Shared as `Meta_DE`; likely operator ingress or relay infrastructure | 2023-09-19 |
| `94.228.169[.]123` | Stager | Ubuntu server embedded as a VBS stager endpoint | 2023-09-20 |
| `178.236.247[.]73` | Stager | Second Ubuntu stager used in the same VBS build | 2023-09-20 |
| `94.228.169[.]143` | Test RDP / launch host | RDP system used to execute the VBS and validate callbacks | 2023-09-20 |
| `91.191.209[.]110` | DarkGate-related server | Shared as a main server in DarkGate testing and setup discussion | 2023-09-21 |
| `5.8.18[.]230` / `rokllold279[.]com` | COBA proxy | Proxy node for a COBA 4.8 teamserver pair | 2023-09-21 |
| `45.227.254[.]7` | COBA teamserver | COBA 4.8 server paired with `rokllold279[.]com` | 2023-09-21 |
| `88.214.25[.]250` / `rokllofrold29[.]com` | COBA proxy | Proxy node forwarding to a separate COBA teamserver | 2023-09-21 |
| `194.165.17[.]9` | COBA teamserver | Teamserver paired with `rokllofrold29[.]com` | 2023-09-21 |
| `88.214.26[.]31` / `tsvsnjv[.]com` | COBA proxy | Additional proxy pair described as `cob4` | 2023-09-21 |
| `194.165.16[.]19` | COBA teamserver | Teamserver paired with `tsvsnjv[.]com` | 2023-09-21 |
| `46.161.27[.]152` / `lkcagar[.]com` | COBA proxy | Proxy node for the `cob5` stack | 2023-09-24 |
| `141.98.81[.]48` | COBA teamserver | `cob5` teamserver with port `38400` noted in the logs | 2023-09-24 |
| `104.238.60[.]64` | Testing RDP | RDP with Excel used during XLL and delivery validation | 2023-09-21 |
| `45.155.249[.]55` | Brute Ratel listener | Brute Ratel test listener used during October 2023 experimentation | 2023-10 |
| `51.89.62[.]202` | Multi-port infrastructure | Shared with multiple ports under `EDC` in November 2023 | 2023-11 |
| `91.191.209[.]70` | COBA teamserver | Later COBA teamserver referenced in the wider corpus | 2024 |
| `141.98.9[.]152` | COBA teamserver | Later COBA teamserver referenced in the wider corpus | 2024 |
| `179.60.149[.]10` | COBA teamserver | Later COBA teamserver referenced in the wider corpus | 2024 |
| `5.8.18[.]20` | SOCKS / SSH command host | Shared in June 2024 as `ssh cmd,socks` infrastructure | 2024-06 |
| `5.161.250[.]129` | SOCKS node | Shared in June 2024 as a SOCKS endpoint | 2024-06 |
| `91.196.70[.]160` | SOCKS pool | Repeated SOCKS5 endpoints shared in 2024 | 2024-07 |
| `37.1.200[.]232` | SOCKS pool | Repeated SOCKS5 endpoints shared in 2024 | 2024-07 |
| `38.180.0[.]28` | SOCKS pool | Repeated SOCKS5 endpoints shared in 2024 | 2024-07 |
| `38.180.20[.]163` | SOCKS pool | Repeated SOCKS5 endpoints shared in 2024 | 2024-07 |
| `185.142.238[.]31` | SOCKS pool | Repeated SOCKS5 endpoints shared in 2024 | 2024-07 |
| `rdweb-page[.]com` | RDWeb lure / sender domain | Appears in mass-mail configuration-style data | 2024 |
| `rdweb-page[.]net` | RDWeb lure / sender domain | Appears in mass-mail configuration-style data | 2024 |
| `connectedriver[.]com` | Sender domain | Appears alongside other mail-sender domains in campaign data | 2024 |
| `martiangathering[.]com` | Sender domain | Appears alongside other mail-sender domains in campaign data | 2024 |
| `3kelincijp[.]com` | Sender domain | Appears alongside other mail-sender domains in campaign data | 2024 |
| `backconnect[.]org` | SOCKS bot distribution | Used to generate or deliver backconnect SOCKS bot builds | 2024 |
| `ghostsocks[.]net` | SOCKS bot support | Mentioned as related SOCKS infrastructure in 2024 | 2024 |
| `kingprovpn[.]com` | VPN-related service | Referred to in 2024 operator discussions | 2024 |
| `temp[.]sh` | Payload hosting | Used repeatedly to stage VBS archives and binary payloads | 2023-09-20 |
| `qaz[.]im` | Alternate payload hosting | Used when `temp.sh` was unstable during XLL delivery testing | 2023-09-21 |

## Infrastructure by Function

### Command and Control

| Indicator | Notes |
| --- | --- |
| `147.78.47[.]48` | Dedicated Cobalt Strike server mentioned during setup |
| `45.227.254[.]7` | COBA teamserver behind `rokllold279[.]com` |
| `194.165.17[.]9` | COBA teamserver behind `rokllofrold29[.]com` |
| `194.165.16[.]19` | COBA teamserver behind `tsvsnjv[.]com` |
| `141.98.81[.]48` | COBA `cob5` teamserver behind `lkcagar[.]com` |
| `91.191.209[.]110` | Shared during DarkGate staging and testing |
| `91.191.209[.]70` | Later COBA teamserver referenced in the wider corpus |
| `141.98.9[.]152` | Later COBA teamserver referenced in the wider corpus |
| `179.60.149[.]10` | Later COBA teamserver referenced in the wider corpus |

### Proxy, Redirector, and SOCKS Layer

| Indicator | Notes |
| --- | --- |
| `88.214.26[.]33` / `betshopkipstri[.]com` | Explicitly described as a Cobalt Strike proxy |
| `5.8.18[.]230` / `rokllold279[.]com` | COBA proxy |
| `88.214.25[.]250` / `rokllofrold29[.]com` | COBA proxy |
| `88.214.26[.]31` / `tsvsnjv[.]com` | COBA proxy |
| `46.161.27[.]152` / `lkcagar[.]com` | COBA proxy with firewall testing |
| `5.8.18[.]20` | SOCKS and SSH command host |
| `5.161.250[.]129` | SOCKS node |
| `91.196.70[.]160`, `37.1.200[.]232`, `38.180.0[.]28`, `38.180.20[.]163`, `185.142.238[.]31` | Later SOCKS pools repeatedly shared in internal exchanges |
| `backconnect[.]org` | Backconnect SOCKS bot builder or distribution point |
| `ghostsocks[.]net` | GhostSocks-related support infrastructure |

### VPN and Operator Access

| Indicator | Notes |
| --- | --- |
| `179.60.149[.]235` | Shared as `Meta_US` |
| `88.214.25[.]244` | Shared as `Meta_DE` |
| `torguard[.]net` | Mentioned early in operator setup |
| `oppvn5[.]ovpn` | Single-VPN configuration filename shared during setup |
| `kingprovpn[.]com` | Later VPN-related service reference |

### Payload Staging and Delivery

| Indicator | Notes |
| --- | --- |
| `https[:]//temp[.]sh/bpmcR/Download_VBS_slush[.]rar` | VBS payload archive |
| `https[:]//temp[.]sh/AWvjU/cob1_443_x86[.]bin` | Payload binary hosted for distribution |
| `https[:]//temp[.]sh/BQGxO/Download_VBS_shaft[.]rar` | Additional VBS archive used in testing |
| `https[:]//temp[.]sh/aXTBv/Download_VBS_lava[.]rar` | Additional VBS archive |
| `qaz[.]im` links | Replacement delivery links used for XLL, PDF, and MSI packaging |
| `https[:]//dropmefiles[.]com/4WjCy` | Shared during October 2023 database and access-list exchanges |
| `rdweb-page[.]com`, `rdweb-page[.]net`, `connectedriver[.]com`, `martiangathering[.]com`, `3kelincijp[.]com` | Later sender-domain or lure-domain style infrastructure |

### Test Systems and Victim-Side Launch Points

| Indicator | Notes |
| --- | --- |
| `94.228.169[.]143` | RDP bot host used to execute staged VBS |
| `104.238.60[.]64` | RDP shared for Excel/XLL validation |
| `172.20.10[.]3` | Internal address from an initial beacon on 2023-09-25 |

### Remote Access Validation and Brute-Force Infrastructure

| Indicator | Notes |
| --- | --- |
| `VALID_BRUT_RDWEB.txt` | File naming convention indicating validated or brute-forced RDWeb access sets |
| `VALID_BRUT_CISCO.txt` | File naming convention indicating validated or brute-forced Cisco access sets |
| `FORTI_VALID.txt` | Fortinet validation set |
| `AUTH_VALID.txt` | Generic authentication validation set |
| `SONIC_VALID.txt` | SonicWall validation set |
| `WG_VALID.txt` | WireGuard validation set |
| `CISCO_VALID_ITEMS.txt` | Cisco validation set |

### Virtualization and Locker Operations

| Indicator | Notes |
| --- | --- |
| `/tmp/encryptor -killesxi` | ESXi locker execution pattern |
| `esxcli vm process list` | VM enumeration prior to impact |
| `esxcli system settings encryption set --require-exec-installed-only=F` | ESXi configuration change associated with locker execution |
| `.przhow632` | File extension mentioned in post-encryption support and decryptor troubleshooting |

## Operational Takeaways

- The actor separated proxy, teamserver, and staging nodes rather than relying on a single host.
- `temp.sh` and `qaz.im` were central to payload delivery and should be treated as recurring pivot points for this cluster.
- Multiple COBA stacks were rotated over a short period, which suggests disposable infrastructure and frequent rebuilds.
- VPN discovery and operator-access discussion centered on Cisco, Citrix, GlobalProtect, FortiClient, and SonicWall environments.
- By 2024, the operation visibly expanded into validated VPN and RDWeb credential pipelines, large SOCKS pools, and mail-sender or lure-domain infrastructure.
- The 2024 infrastructure picture is less about a single payload chain and more about scale: access validation, SOCKS distribution, and operational support for encryption and decryption workflows.

## Enrichment Priorities

1. Pivot passive DNS on `betshopkipstri[.]com`, `rokllold279[.]com`, `rokllofrold29[.]com`, `tsvsnjv[.]com`, and `lkcagar[.]com`.
2. Look for historical TLS and hosting overlap between `147.78.47[.]48`, `45.227.254[.]7`, `194.165.17[.]9`, `194.165.16[.]19`, and `141.98.81[.]48`.
3. Hunt for short-lived downloads from `temp.sh`, `qaz.im`, and `dropmefiles[.]com` around mail-delivery timestamps.
4. Review internal proxy, VPN, and RDP logs for contact with the stager pair `94.228.169[.]123` and `178.236.247[.]73`.
5. Pivot on `rdweb-page[.]com`, `rdweb-page[.]net`, `backconnect[.]org`, `ghostsocks[.]net`, and the recurring SOCKS IPs to identify later campaign infrastructure.
