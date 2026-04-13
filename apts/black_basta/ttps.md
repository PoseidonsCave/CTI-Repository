# Black Basta MITRE ATT&CK Mapping

This ATT&CK mapping is based on behaviors explicitly described in the Black Basta source material. The goal is to capture what was observed and make it easier to connect those behaviors to ATT&CK without speculating beyond the evidence.

## Resource Development

| ATT&CK ID | Technique | Evidence from the Logs |
| --- | --- | --- |
| `T1583` | Acquire Infrastructure | Participants repeatedly acquired and rotated servers, proxies, VPN nodes, staging hosts, and later SOCKS infrastructure |
| `T1583.001` | Acquire Infrastructure: Domains | Domains such as `betshopkipstri[.]com`, `rokllold279[.]com`, `rokllofrold29[.]com`, `tsvsnjv[.]com`, `lkcagar[.]com`, and later `rdweb-page[.]com` were used as redirectors or delivery infrastructure |
| `T1583.003` | Acquire Infrastructure: Virtual Private Server | Multiple VPS-like systems were used as proxy, C2, staging, SOCKS, and validation hosts |
| `T1583.006` | Acquire Infrastructure: Web Services | `temp.sh`, `qaz.im`, and later `dropmefiles[.]com` were used to host delivery content or exchanged datasets |
| `T1588.001` | Obtain Capabilities: Malware | The corpus includes discussions of DarkGate, Nighthawk, Brute Ratel, and purchased tooling |

## Initial Access

| ATT&CK ID | Technique | Evidence from the Logs |
| --- | --- | --- |
| `T1566.001` | Phishing: Spearphishing Attachment | The logs describe sending VBS, XLL, PDF, MSI, and LNK-based payloads into Europe and other target sets |
| `T1204.002` | User Execution: Malicious File | The delivery chain relied on recipients opening attachments and enabling Excel add-ins |
| `T1133` | External Remote Services | Repeated use of RDP and VPN-backed access was discussed for victim environments |
| `T1078` | Valid Accounts | Large-scale validated VPN, RDWeb, and enterprise remote-access credentials were exchanged and operationalized |

## Execution

| ATT&CK ID | Technique | Evidence from the Logs |
| --- | --- | --- |
| `T1059.005` | Command and Scripting Interpreter: Visual Basic | VBS payloads were a recurring delivery and staging mechanism |
| `T1218` | System Binary Proxy Execution | MSI-based delivery and living-process launch discussion align with proxy execution behavior |
| `T1059.004` | Command and Scripting Interpreter: Unix Shell | ESXi-focused `esxcli`, `find`, `nohup`, and encryptor command lines were shared directly in the logs |

## Privilege Escalation and Defense Evasion

| ATT&CK ID | Technique | Evidence from the Logs |
| --- | --- | --- |
| `T1055` | Process Injection | The logs explicitly describe injecting shellcode into other processes and moving loaders into live processes |
| `T1027` | Obfuscated or Compressed Files and Information | The actor iterated on crypted builds, obfuscated VBS, and archive-wrapped payloads |
| `T1036` | Masquerading | PDF decoys, renamed extensions, and benign-looking process names were used to hide payload execution |
| `T1218.007` | System Binary Proxy Execution: Msiexec | MSI was used as an alternate payload container during delivery troubleshooting |
| `T1562.001` | Impair Defenses: Disable or Modify Tools | Operators discussed Defender outcomes, removing Sentinel, and altering ESXi execution-related settings |

## Discovery

| ATT&CK ID | Technique | Evidence from the Logs |
| --- | --- | --- |
| `T1016` | System Network Configuration Discovery | Participants checked for VPN products and remote-access software |
| `T1018` | Remote System Discovery | `secretsdump.py` usage with `hosts.txt` indicates multi-host targeting and discovery |
| `T1082` | System Information Discovery | Victim environment size, trusts, domain status, and virtualization were actively cataloged |
| `T1049` | System Network Connections Discovery | Participants checked whether bots, relays, proxies, RDP launches, and SOCKS infrastructure were connecting where expected |
| `T1518` | Software Discovery | The logs include checks for FortiClient, GlobalProtect, SonicWall, Citrix, and security tooling such as Sentinel |

## Credential Access

| ATT&CK ID | Technique | Evidence from the Logs |
| --- | --- | --- |
| `T1003` | OS Credential Dumping | `secretsdump.py` usage and repeated hash-file references were observed |
| `T1558.003` | Steal or Forge Kerberos Tickets: Kerberoasting | A `$krb5tgs$` service ticket hash was posted on September 21 and later Kerberoast artifacts were shared again in 2024 |
| `T1056.001` | Input Capture: Keylogging | One participant described an active keylogger on a user who regularly logged into Cisco |
| `T1110` | Brute Force | Later 2024 material includes RDWeb and VPN brute-force or high-volume validation activity |

## Lateral Movement and Command and Control

| ATT&CK ID | Technique | Evidence from the Logs |
| --- | --- | --- |
| `T1021.001` | Remote Services: Remote Desktop Protocol | RDP hosts were used for launching, testing, and pivoting |
| `T1021.004` | Remote Services: SSH | SSH access to operator infrastructure and likely Linux-side support systems was a routine part of the workflow |
| `T1090` | Proxy | The group layered proxy infrastructure in front of C2 and staging systems and later used large SOCKS pools |
| `T1071.001` | Application Layer Protocol: Web Protocols | Payload hosting, redirectors, and callbacks relied on HTTP or HTTPS |
| `T1105` | Ingress Tool Transfer | Malware, payload binaries, archives, and tooling were staged and transferred through external infrastructure |
| `T1573` | Encrypted Channel | Onion services, HTTPS staging, and remote-admin tooling imply encrypted delivery and management channels |

## Impact

| ATT&CK ID | Technique | Evidence from the Logs |
| --- | --- | --- |
| `T1486` | Data Encrypted for Impact | Operators explicitly claimed they had "locked" victim networks and later discussed decryptor issues |
| `T1489` | Service Stop | ESXi-specific locker commands and VM-stop discussions indicate service or workload interruption before or during encryption |

## Analytic Notes

- The strongest ATT&CK mappings from this dataset are `T1566.001`, `T1078`, `T1003`, `T1558.003`, `T1021.001`, `T1090`, `T1105`, and `T1486`.
- Delivery variants and loader behavior evolved quickly across the observed corpus, especially as the group moved from attachment testing into validated VPN and RDWeb access operations.
- The longer-range 2024 corpus adds strong support for `T1078`, `T1110`, ESXi-focused shell execution, and later decryptor troubleshooting.
