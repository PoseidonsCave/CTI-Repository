# Black Basta Indicators of Compromise

The indicators below were extracted from the full Black Basta source set and sanitized for defensive use. Working credentials seen in the material are not reproduced.

## Priority Network Indicators

### Domains and Services

| Indicator | Type | Context |
| --- | --- | --- |
| `matrix[.]bestflowers247[.]online` | Internal communications | Primary Matrix server used by the group |
| `matrixtcFJHPDblmt2rg[.]network` | Internal communications | Secondary Matrix server used by the group |
| `betshopkipstri[.]com` | Redirector / proxy | Cobalt Strike proxy host |
| `rokllold279[.]com` | Redirector / proxy | COBA proxy domain |
| `rokllofrold29[.]com` | Redirector / proxy | COBA proxy domain |
| `tsvsnjv[.]com` | Redirector / proxy | COBA proxy domain |
| `lkcagar[.]com` | Redirector / proxy | COBA proxy domain |
| `temp[.]sh` | File hosting | VBS and binary payload staging |
| `qaz[.]im` | File hosting | Alternate XLL, PDF, MSI, and VBS staging |
| `backconnect[.]org` | SOCKS bot support | Used to generate or retrieve backconnect builds |
| `ghostsocks[.]net` | SOCKS bot support | Associated with GhostSocks references in 2024 |
| `rdweb-page[.]com` | Likely lure or sender domain | Appears in mailer-style configuration data |
| `rdweb-page[.]net` | Likely lure or sender domain | Appears in mailer-style configuration data |
| `connectedriver[.]com` | Sender or lure domain | Appears in mailer-style configuration data |
| `martiangathering[.]com` | Sender or lure domain | Appears in mailer-style configuration data |
| `3kelincijp[.]com` | Sender or lure domain | Appears in mailer-style configuration data |
| `kingprovpn[.]com` | VPN-related service | Referenced in internal conversations |

### Onion Services

| Indicator | Context |
| --- | --- |
| `orders44vz5yl7y6xajzxsdo2n6niaqu73ty4tx6ncwqnc752yzae4ad[.]onion` | Cobalt Strike hosting test |
| `stniiomyjliimcgkvdszvgen3eaaoz55hreqqx6o77yvmpwt7gklffqd[.]onion` | Leak blog |
| `bpeln2aqs66qqfuex2cvcyjiy5ggcwbyh5nbmxzxt6daamkmpmufv4qd[.]onion` | Admin panel |

### IP Addresses

| Indicator | Role |
| --- | --- |
| `88.214.26[.]33` | Cobalt Strike proxy |
| `147.78.47[.]48` | Dedicated Cobalt Strike server |
| `179.60.149[.]235` | VPN node |
| `88.214.25[.]244` | VPN node |
| `94.228.169[.]123` | VBS stager |
| `178.236.247[.]73` | VBS stager |
| `94.228.169[.]143` | RDP launch / test host |
| `91.191.209[.]110` | DarkGate-related server |
| `176.174.149[.]37` | DarkGate-related infrastructure reference |
| `5.8.18[.]230` | COBA proxy |
| `45.227.254[.]7` | COBA teamserver |
| `88.214.25[.]250` | COBA proxy |
| `194.165.17[.]9` | COBA teamserver |
| `88.214.26[.]31` | COBA proxy |
| `194.165.16[.]19` | COBA teamserver |
| `46.161.27[.]152` | COBA proxy |
| `141.98.81[.]48` | COBA teamserver |
| `104.238.60[.]64` | RDP used for XLL testing |
| `172.20.10[.]3` | Internal host from an initial beacon |
| `45.155.249[.]55` | Brute Ratel test listener |
| `51.89.62[.]202` | Multi-port infrastructure node |
| `91.191.209[.]70` | Later COBA teamserver |
| `141.98.9[.]152` | Later COBA teamserver |
| `179.60.149[.]10` | Later COBA teamserver |
| `5.8.18[.]20` | SOCKS / SSH command host |
| `5.161.250[.]129` | SOCKS node |
| `91.196.70[.]160` | SOCKS pool |
| `37.1.200[.]232` | SOCKS pool |
| `38.180.0[.]28` | SOCKS pool |
| `38.180.20[.]163` | SOCKS pool |
| `185.142.238[.]31` | SOCKS pool |

## Delivery and Payload URLs

| Indicator | Context |
| --- | --- |
| `https[:]//temp[.]sh/bpmcR/Download_VBS_slush[.]rar` | VBS archive |
| `https[:]//temp[.]sh/BQGxO/Download_VBS_shaft[.]rar` | VBS archive |
| `https[:]//temp[.]sh/aXTBv/Download_VBS_lava[.]rar` | VBS archive |
| `https[:]//temp[.]sh/AWvjU/cob1_443_x86[.]bin` | Payload binary |
| `http[:]//88.119.175[.]245/WNJD1/LDmdkA` | Randomized delivery link observed during XLL debugging |
| `http[:]//94.228.169[.]143:2351/vjikfjxb` | Hardcoded link referenced during XLL/VBS troubleshooting |
| `https[:]//dropmefiles[.]com/4WjCy` | Database or access-list exchange link referenced in October 2023 |

## Host and Detection Artifacts

### File and Delivery Artifacts

| Artifact | Context |
| --- | --- |
| `XLL` | Preferred Europe-focused attachment format by September 26 |
| `VBS` | Common payload wrapper and launcher |
| `MSI` | Used as a replacement extension to avoid immediate detection |
| `LNK` | Mentioned as an alternate delivery method requiring DLL support |
| `PDF + XLL` | Decoy-plus-payload combination used in testing |
| `.przhow632` | Post-encryption file extension referenced during decryptor support |
| `FORTI_VALID.txt` | Fortinet validation set |
| `AUTH_VALID.txt` | Authentication validation set |
| `SONIC_VALID.txt` | SonicWall validation set |
| `WG_VALID.txt` | WireGuard validation set |
| `CISCO_VALID_ITEMS.txt` | Cisco validation set |
| `VALID_BRUT_RDWEB.txt` | RDWeb validation or brute-force set |
| `VALID_BRUT_CISCO.txt` | Cisco validation or brute-force set |

### Registry and VPN Discovery Artifacts

The logs include explicit checks for common enterprise VPN products. These strings are useful for retrospective EDR, Sysmon, PowerShell, and command-line hunting.

| Artifact | Context |
| --- | --- |
| `HKLM\\SOFTWARE\\Cisco` | VPN discovery |
| `HKLM\\SYSTEM\\CurrentControlSet\\services\\Citrix User Profile Manager` | Citrix discovery |
| `HKLM\\SOFTWARE\\Palo Alto Networks\\GlobalProtect\\PanGPS` | GlobalProtect discovery |
| `HKLM\\SOFTWARE\\Palo Alto Networks\\GlobalProtect\\Settings` | GlobalProtect discovery |
| `HKLM\\SOFTWARE\\Fortinet\\FortiClient` | FortiClient discovery |
| `HKLM\\Software\\Fortinet\\FortiClient\\Sslvpn\\Tunnels` | FortiClient discovery |
| `HKLM\\SOFTWARE\\SonicWall\\SSL-VPN NetExtender\\Standalone` | SonicWall discovery |
| `HKLM\\SOFTWARE\\SonicWall\\SSL-VPN NetExtender\\Standalone\\Profiles` | SonicWall discovery |
| `C:\\Program Files\\Palo Alto Networks\\GlobalProtect\\PanGPA.exe` | Host artifact |

### Command and Tooling Artifacts

| Artifact | Context |
| --- | --- |
| `proxychains python3 secretsdump.py ... -inputfile hosts.txt` | Credential dumping at scale through a proxy |
| `./teamserver <ip> <password> ./xxxx.profile` | COBA / teamserver launch pattern |
| `Trojan:Script/ObfusScript.A!ml` | Defender detection observed during VBS testing |
| `Nighthawk` | Payload or framework named in testing on September 23 |
| `DarkGate` | Malware and loader testing referenced repeatedly |
| `Brute Ratel` | Operator-tested post-exploitation framework referenced in October 2023 |
| `Rubeus.exe kerberoast /format:hashcat /outfile:C:\Users\Public\kekhash.txt` | Kerberoast collection artifact |
| `nohup sh -c '/tmp/encryptor -killesxi'` | ESXi locker execution string |
| `esxcli system settings encryption set --require-exec-installed-only=F` | ESXi configuration change associated with locker activity |

## Victim and Targeting References

These are not malicious indicators by themselves, but they are useful scoping pivots for incident response, victim notification, and historical correlation.

| Indicator | Context |
| --- | --- |
| `miratechgroup[.]com` | Live-access discussion on September 20 |
| `mymiratech[.]com` | Alternate internal domain reference tied to the same access |
| `tanatexchemicals[.]com` | Operator target-handling discussion on September 20 |
| `metricstream[.]com` | Domain access and system info discussion on September 21 |
| `ingeus[.]co[.]uk` | Kerberos hash and access discussion |
| `fortive[.]com` | High-value victim profiling and later credential activity |
| `alsoenergy[.]com` | Enterprise VPN access list reference |
| `ticketmaster[.]com` | Enterprise VPN access list reference |
| `medline[.]com` | Enterprise VPN access list reference |
| `bell[.]ca` | Enterprise VPN access list reference |
| `ameritrustgroup[.]com` | Target needing SOCKS-enabled access |
| `innophos[.]com` | Target needing SOCKS-enabled access |

## Analyst Notes

- The most stable malicious pivots in this set are the COBA proxy and teamserver pairs, `temp.sh` delivery paths, and the staged RDP infrastructure.
- XLL, VBS, and MSI were swapped repeatedly to evade detection and improve delivery rates.
- VPN product discovery strings are high-value host artifacts because they map directly to the actor's target selection workflow.
- The 2024 corpus adds a second major cluster of pivots around validated VPN and RDWeb access, GhostSocks or backconnect infrastructure, and ESXi locker operations.
