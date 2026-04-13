# Black Basta Timeline

This timeline reflects the main date coverage visible in the Black Basta source material. The densest timestamped activity runs from 2023-09-18 through 2024-09-02. Later 2024 references are mostly isolated filenames and artifacts rather than continuous timestamped chat activity.

## 2023-09-18 to 2023-09-30

- The group used `matrix[.]bestflowers247[.]online` and related Matrix rooms as a day-to-day collaboration environment.
- Early setup centered on VPN sourcing, Cobalt Strike and COBA infrastructure, paid hash cracking, and preparing staging capacity.
- The group shared and tested proxy, VPN, onion, and teamserver infrastructure, including `betshopkipstri[.]com`, `147.78.47[.]48`, `orders44vz5yl7y6xajzxsdo2n6niaqu73ty4tx6ncwqnc752yzae4ad[.]onion`, `5.8.18[.]230`, `45.227.254[.]7`, and later `46.161.27[.]152` with `141.98.81[.]48`.
- Delivery development focused on VBS, XLL, PDF decoys, MSI fallback, DarkGate references, and RDP-based testing with stagers such as `94.228.169[.]123` and `178.236.247[.]73`.
- Victim handling discussions included `miratechgroup[.]com`, `tanatexchemicals[.]com`, `metricstream[.]com`, `ingeus[.]co[.]uk`, `edwardian[.]com`, `stantonwilliams[.]com`, and `baccarat[.]com`.
- The logs include discussion of Kerberos material, `secretsdump.py`, keylogger output, initial beacons, and campaign send volume into Europe.

## 2023-10

- The operation shifted from basic delivery testing to scaling access and improving reliability.
- Participants asked for a clean dropper, discussed crypting builds, shellcode injection into processes, and re-uploading HVNC.
- Spam infrastructure and mailing throughput became a recurring topic, including requests for a "normal spam department" and references to large credential or target bases.
- Valid enterprise access lists started appearing in bulk, including Cisco AnyConnect, GlobalProtect, Pulse Secure, and other VPN portals tied to organizations such as `alsoenergy.com`, `ticketmaster.com`, `enercon.de`, `medline.com`, and `bell.ca`.
- Participants evaluated or attempted to operationalize Brute Ratel, including private manuals, payload compilation steps, and a test listener on `45.155.249[.]55:443`.
- Fortive-related victim profiling appeared with a detailed victim summary citing `2624+` servers, `34` vCenters, `189` ESXi systems, and `BASTA 2.0` notes.
- DarkGate delivery also remained active, including discussion of loading a DarkGate JavaScript file through `curl`.

## 2023-11

- ESXi-focused ransomware operations became explicit.
- Participants shared ESXi command sequences such as `esxcli vm process list`, `ps -i | grep encryptor`, `nohup sh -c '/tmp/encryptor -killesxi'`, and `esxcli system settings encryption set --require-exec-installed-only=F`.
- Chat participants discussed testing lockers on their own ESXi instances, confirming whether new locker builds had been loaded, and troubleshooting whether virtual machines had been shut down correctly.
- Additional infrastructure and victim-network cleanup discussions referenced older network sets and FTP-based follow-on handling.

## 2023-12

- Post-compromise operations and privilege escalation efforts became more visible.
- Participants discussed the appearance of Sentinel on a host after access had already been established and considered removing or bypassing it.
- They monitored open administrative PowerShell sessions, waited for repeated privileged user behavior, and discussed how to obtain higher privileges without domain admins routinely logging onto the network.
- Credential and Kerberos material continued to circulate, including host- or victim-specific artifacts such as `FLYT.schwanshs.net`.

## 2024-01

- Extortion and leak-site timing surfaced more clearly, including arguments over whether a victim should have remained unpublished until a later deadline.
- Kerberoast-style material and crack analysis remained active, with examples of `$krb5tgs$` hashes and discussion of password patterns recoverable from service-account naming conventions.
- The operational tempo stayed active immediately after the new year rather than pausing for long.

## 2024-02 to 2024-03

- The corpus volume increases significantly in February and March, indicating sustained activity, but the sampled material remains more fragmented than the September 2023 slice.
- Themes that continue through this period include credential handling, Kerberos material, infrastructure reuse, and preparation for larger-scale access operations.

## 2024-04

- The operation showed a visible shift toward remote-access credential validation and infrastructure scaling.
- Operators discussed server capacity in terms of tens of thousands of concurrent flows and debated buying additional servers from a hosting provider to keep up.
- Validation lists were shared for multiple access classes, including `FORTI_VALID.txt`, `AUTH_VALID.txt`, `SONIC_VALID.txt`, `WG_VALID.txt`, `CISCO_VALID_ITEMS.txt`, `VALID_BRUT_RDWEB.txt`, and `VALID_BRUT_CISCO.txt`.
- This period shows the group maturing from malware-delivery experimentation into industrialized validation of enterprise remote-access pathways.

## 2024-05 to 2024-06

- Locker operations, SOCKS infrastructure, and victim support remained active.
- Participants exchanged SOCKS endpoints and requested more SOCKS capacity to work specific targets such as `ameritrustgroup.com` and `innophos.com`.
- Support issues surfaced, including complaints that encrypted files with the extension `.przhow632` were skipped by a decryption utility because keys were missing.
- Translation or support mediation between operators and a coder also appears, suggesting live troubleshooting with victims or affiliates after encryption events.

## 2024-07 to 2024-08

- The access model appears even more focused on remote access, brute-force scale, and SOCKS distribution.
- The corpus includes large SOCKS inventories, repeated `socks5://` endpoint dumps, `ghostsocks` references, and `backconnect` builder links.
- The logs reference `Rubeus.exe kerberoast /format:hashcat /outfile:C:\Users\Public\kekhash.txt`.
- Bulk RDWeb and VPN brute-force or validation activity appears in the logs, including references to `rdweb-page[.]com`, `rdweb-page[.]net`, and many invalid root-password or invalid-credential results from scanning or brute-force workflows.
- The logs explicitly note that RDWeb consumed far more traffic when run at full capacity.

## 2024-09

- The visible tempo slows sharply compared with spring and summer 2024.
- Participants discussed still being on break until mid-September and referenced an Ethereum transaction through the MetaMask portfolio page.
- The reduced volume suggests a temporary lull rather than a clean shutdown.

## Late 2024 Residual Artifacts

- The corpus still contains isolated strings carrying October 2024 dates, such as `EV32PRIMAKLLC2024-10-02[GlobalSign].rar`, but not dense timestamped October through December 2024 chat activity.
- The practical timeline coverage for behavior is therefore best treated as September 2023 through September 2024, with scattered late-2024 artifact references.

## Assessment

- The earliest well-formed operational timeline in this corpus begins in mid-September 2023, not January 2023.
- The most important strategic change over time is the shift from delivery-chain testing in late 2023 to large-scale VPN, RDWeb, SOCKS, and credential-validation operations in 2024.
- By 2024, the logs also show mature locker operations, ESXi-specific tradecraft, brute-force or validation infrastructure, and victim-side decryptor troubleshooting.