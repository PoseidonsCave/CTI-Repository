# Black Basta Investigation Opportunities

This file turns the Black Basta source material into concrete investigative leads, hunts, and detection opportunities across the broader corpus, not just the September 2023 subset.

## Immediate Scoping Actions

1. Hunt for connections to the proxy and teamserver infrastructure listed in `iocs.md`, with priority on `88.214.26[.]33`, `147.78.47[.]48`, `5.8.18[.]230`, `45.227.254[.]7`, `88.214.25[.]250`, `194.165.17[.]9`, `88.214.26[.]31`, `194.165.16[.]19`, `46.161.27[.]152`, `141.98.81[.]48`, and `45.155.249[.]55`.
2. Search outbound proxy, web, and DNS logs for `temp[.]sh`, `qaz[.]im`, and `dropmefiles[.]com` downloads around suspicious email or user-execution activity.
3. Review RDP, VPN, and jump-host telemetry for contact with the stager pair `94.228.169[.]123` and `178.236.247[.]73`.
4. Hunt for endpoints that accessed `miratechgroup[.]com`, `mymiratech[.]com`, `tanatexchemicals[.]com`, `metricstream[.]com`, or `ingeus[.]co[.]uk` close to credential theft, suspicious RDP use, or beaconing.
5. Extend scoping into the 2024 infrastructure and victim references: `rdweb-page[.]com`, `rdweb-page[.]net`, `backconnect[.]org`, `ghostsocks[.]net`, `fortive[.]com`, `ameritrustgroup[.]com`, and `innophos[.]com`.

## Endpoint Hunting Leads

### XLL, VBS, MSI, and LNK Delivery

The logs show repeated experimentation with XLL, VBS, MSI, PDF decoys, and LNK-based delivery.

Prioritize hunts for:

- `excel.exe` spawning `wscript.exe`, `cscript.exe`, `msiexec.exe`, or unexpected child processes.
- File creation of `.xll`, `.vbs`, `.msi`, and `.lnk` in user download, temp, and email-attachment paths.
- Office or browser-driven downloads from `temp.sh`, `qaz.im`, or `dropmefiles[.]com`.
- Defender detections or suppressions around `Trojan:Script/ObfusScript.A!ml`.

### Injection and Loader Behavior

The logs describe shellcode loading into live processes and name examples such as `werfault`, `waahost`, and `gpupdate`.

Hunt for:

- Unexpected child processes of `explorer.exe` that immediately receive injected memory or network connections.
- Short-lived process chains where `werfault.exe`, `waahost.exe`, or `gpupdate.exe` make outbound connections without a legitimate parent or command line.
- Memory allocation, write, and execute sequences associated with shellcode injection.

### ESXi Locker Activity

The later 2023 corpus includes direct ESXi locker operations.

Hunt for:

- Execution of `esxcli vm process list`, `esxcli system settings encryption get`, or `esxcli system settings encryption set --require-exec-installed-only=F` on ESXi hosts that were not under active maintenance.
- Shell histories, audit logs, or EDR telemetry showing `nohup sh -c '/tmp/encryptor -killesxi'` or similar locker execution patterns.
- Sudden VM stoppage, failed VM process shutdown attempts, or newly placed locker binaries on ESXi datastores.
- Backup or FTP activity immediately before impact, since operators also referenced exfil or backup movement in victim summaries.

### VPN and Remote Access Discovery

The group explicitly checked for Cisco, Citrix, GlobalProtect, FortiClient, and SonicWall artifacts to determine whether a compromised environment had reusable remote access.

Hunt for:

- `reg query` executions against the VPN-related registry paths listed in `iocs.md`.
- Command-line access to `PanGPA.exe` or other installed VPN client binaries outside normal user activity.
- Operator use of RDP followed by VPN discovery and credential harvesting on the same host.

### VPN and RDWeb Validation at Scale

By 2024, the logs show the group validating VPN and RDWeb access at scale, including file sets like `FORTI_VALID.txt`, `SONIC_VALID.txt`, `WG_VALID.txt`, `VALID_BRUT_RDWEB.txt`, and `VALID_BRUT_CISCO.txt`.

Hunt for:

- Bulk validation against VPN portals, RDWeb, or SSL VPN services from common source infrastructure.
- Authentication attempts spanning Cisco, Fortinet, SonicWall, GlobalProtect, Pulse Secure, or RDWeb endpoints with the same operator infrastructure.
- Traffic or mail artifacts tied to `rdweb-page[.]com` or `rdweb-page[.]net`, which appear consistent with sender-domain or lure-domain staging.
- Sudden increases in SOCKS usage or authenticated outbound proxy chains prior to successful remote access.

### Credential Access and Domain Enumeration

The logs include direct references to `secretsdump.py`, `proxychains`, Kerberos tickets, NTLM material, and domain validation work.

Hunt for:

- `secretsdump.py` execution, especially with `proxychains` or `-inputfile hosts.txt`.
- Kerberoasting-like activity, including unusual service ticket requests and `$krb5tgs$` artifacts.
- Lateral movement from workgroup systems into domain-joined systems following RDP compromise.
- Creation or collection of files named like `kekhash.txt` and similarly themed hash dumps.
- Use of `Rubeus.exe kerberoast /format:hashcat /outfile:C:\Users\Public\kekhash.txt` or close variants.
- Privilege escalation attempts timed around open admin PowerShell sessions, especially on hosts where Sentinel or similar tooling appeared after initial compromise.

## Network Detection Opportunities

### Proxy and Teamserver Ports

Multiple proxy domains exposed the same port pattern: `80`, `443`, `8080`, `8888`, `7575`, and `4444`.

Investigate:

- Endpoints contacting uncommon external hosts on these ports shortly after email attachment execution.
- Internal systems making repeated low-volume egress to the same host over several alternate ports.
- TLS sessions to newly seen domains that map to ephemeral VPS hosting.

### SOCKS and Backconnect Infrastructure

The 2024 corpus contains recurring SOCKS pools, GhostSocks references, and `backconnect.org` builder links that support remote access at scale.

Investigate:

- Systems contacting `backconnect[.]org` or `ghostsocks[.]net`.
- Outbound traffic to the recurring SOCKS pool IPs documented in `iocs.md`.
- Egress consistent with transient or rotating SOCKS5 endpoints rather than stable enterprise proxies.

### RDP-Centric Staging

The logs show payloads being launched from dedicated RDP hosts and include troubleshooting around whether callbacks came from the RDP host or the staging server.

Investigate:

- RDP systems that later show outbound web requests to file-sharing sites or callback traffic to teamservers.
- External RDP login followed by download activity from `temp.sh`, `qaz.im`, or hardcoded HTTP links.
- Beaconing from systems that were described internally as not yet being on the network.

### Post-Encryption and Decryptor Support

The June 2024 material shows the group supporting or troubleshooting decryption problems for files with the extension `.przhow632`.

Investigate:

- Hosts or file shares containing `.przhow632` artifacts.
- Communications or tickets referencing undecryptable files, missing keys, or skipped files after a decryption attempt.
- Recontact activity between compromised victims and infrastructure already associated with the actor after the main encryption event.

## Case-Specific Leads

### Miratech Access

The actor discussed a bot labeled `3B`, a user frequently logging into Cisco, and live access tied to `miratechgroup[.]com` and `mymiratech[.]com`.

Suggested review actions:

- Review Cisco VPN logs and successful logins for unusual geography or device fingerprints.
- Correlate keylogger-like telemetry or browser credential collection on hosts accessing Miratech resources.
- Check whether short-lived interactive sessions preceded domain access.

### Tanatex Handling

Operators repeatedly told one another not to touch `tanatexchemicals[.]com`, indicating concurrent victim handling or ownership of access.

Suggested review actions:

- Review whether access or scans against Tanatex-related infrastructure overlap with the Black Basta infrastructure set.
- Look for multiple operator sessions or conflicting tooling on the same victim assets.

### MetricStream and Ingeus

The logs show domain-validation references for `metricstream[.]com` and Kerberos hash-related references for `ingeus[.]co[.]uk`.

Defensive pivots:

- Search for authentication anomalies involving `MSI-DC05` or other domain controllers.
- Hunt for service ticket abuse, MSSQL service account activity, or dumped hash material tied to those environments.

### Fortive and Remote-Access Brokerage

The wider corpus repeatedly references `fortive[.]com`, Fortive-related Kerberos material, and very large victim environment summaries.

Defensive pivots:

- Review VPN, SSO, RDWeb, and privileged Windows activity tied to Fortive infrastructure.
- Hunt for signs of pre-ransomware staging in virtualized environments with vCenter, ESXi, or Hyper-V footprints.
- Check for evidence that access was brokered or resold before final deployment.

## Collection Priorities for Incident Response

1. Browser download history and SmartScreen or Defender logs for `temp.sh`, `qaz.im`, and `dropmefiles[.]com`.
2. EDR process trees for Office, script hosts, `msiexec.exe`, and suspicious explorer-child injections.
3. Command history, PowerShell logs, and Sysmon events for `reg query`, `proxychains`, `secretsdump.py`, `Rubeus.exe`, and ESXi locker command lines.
4. VPN client logs and registry access around Cisco, Citrix, GlobalProtect, FortiClient, and SonicWall artifacts.
5. RDP logs and netflow for systems that later beaconed externally or handled suspicious attachment execution.
6. ESXi shell history, syslog, and `hostd` or `vpxa` logs for locker and configuration-change commands.
7. VPN, RDWeb, and SSL VPN authentication telemetry for bulk validation, brute-force, or successful login reuse.
8. Artifact collection for `.przhow632`, `ghostsocks`, `backconnect`, and `kekhash.txt`.

## Defensive Assessment

- This actor cluster blended commodity hosting, disposable redirects, and iterative payload testing rather than relying on one mature delivery chain.
- XLL and VBS delivery failures generated a lot of troubleshooting noise in the logs; those same failures create detection opportunities in real environments.
- VPN artifact discovery is a particularly useful signal because it reflects both victim qualification and post-compromise expansion planning.
- The 2024 corpus shows a major operational broadening into VPN and RDWeb access validation, SOCKS infrastructure management, and victim-side support after encryption.
