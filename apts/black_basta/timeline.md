# 📅 Timeline – Black Basta Logs

## 2023-09-18
**Summary:**

- Initial infrastructure discussions begin.
- Group members coordinate VPN and proxy sources.
- Hash cracking services and workload assignments discussed.
- Actor 'gg' begins laying out early roles in operational setup.

**Behavioral Tags:** #infra_setup #vpn_ops #team_assignment

## 2023-09-19
**Summary:**

- Proxy server infrastructure confirmed (88.214.26[.]33).
- Actors test connectivity, verify software stack readiness.
- Mentions of Onion site for Cobalt Strike payload delivery.
- Actors continue operational setup and role alignment.

**Notable Indicators:**

- `88.214.26[.]33`
- `http[colon]//orders44vz5yl7y6xajzxsdo2n6niaqu73ty4tx6ncwqnc752yzae4ad.onion/`

**Behavioral Tags:** #c2_setup #payload_hosting #infra_validation

## 2023-09-20
**Summary:**

- Actor 'ugway' confirms access to staging domain: `miratechgroup[.]com`.
- Discussion of active control over targets and live access to Tanatex Chemicals systems.
- Credential references appear for RDP bots and domain controller access.
- Actors communicate transitions of control between hands; live beacons noted.

**Notable Indicators:**

- `miratechgroup.com`

**Behavioral Tags:** #domain_access #rdp_creds #live_access #target_tanatex

## 2023-09-21
**Summary:**

- Actors reference 91 XMR transaction for suspected malware purchase from user `Rastafarai`.
- Indicators suggest engagement with DarkGate malware developer.
- Use of malware sandbox platforms confirmed (Hybrid Analysis, Triage).
- ProxyTraff proxy infrastructure cited.
- Payloads delivered via Temp.SH; VBS script under analysis.
- Actor GG continues DarkGate variant discussions (self-spreading malware).

**Notable Indicators:**

- `https[colon]//temp.sh/bpmcR/Download_VBS_slush.rar`
- `https[colon]//forum.exploit.in/topic/228689/`

**Behavioral Tags:** #crypto_ops #osint_awareness #malware_dev #payload_staging #sandbox_evasion

## 2023-09-22
**Summary:**

- Actors dump and share access to multiple C2 infrastructure nodes.
- Each entry contains IP address, root username, and associated passwords.
- Log shows up to five separate nodes, all using root access credentials.
- Likely part of C2 deployment expansion or credential sharing for lateral movement.

**Notable Indicators:**

- `51[.]195[.]49[.]233`
- `94[.]131[.]106[.]78`
- `95[.]164[.]17[.]59`
- `135[.]125[.]177[.]82`
- `135[.]125[.]177[.]95`

**Behavioral Tags:** #infra_expansion #root_creds #c2_ops

## 2023-09-23
**Summary:**

- Actor posts NTLM credential artifact for victim user.
- Artifact appears to be output from credential dumping tool (e.g., secretsdump).
- Additional single hash posted separately (MD5 or password hash).
- Continued credential gathering activity likely from compromised environment.

**Behavioral Tags:** #ntlm_dump #hash_exfil #victim_creds

## 2023-09-24
**Summary:**

- Actor 'yy' posts detailed C2 infrastructure setup for Coba proxy and server nodes.
- Includes IP addresses, SSH ports, login credentials, and payload launch commands.
- Server `141.98.81[.]48` linked to COBA listener on port 38400 with profile injection via teamserver command.
- Mentions port exposure across a wide range (80, 443, 8080, 8888, etc.) for domain `lkcagar[.]com`.

**Behavioral Tags:** #infra_expansion #c2_launch #proxy_ops #server_staging

## 2023-09-25
**Summary:**

- Actor 'lapa' reports financial transfer of 400k units (presumed crypto or internal currency).
- Actor announces intent to stop further actions or pause, suggesting a handoff or burn stage.
- Screenshots are shared within group (possibly evidentiary or task proofing).

**Behavioral Tags:** #financial_ops #handoff #pause_ops

## 2023-09-26
**Summary:**

- Actor 'lapa' proposes targeting Europe using an `.xll` attachment (Excel Add-In payload).
- Actor 'gg' confirms and supports the plan.
- This suggests an upcoming phishing campaign involving document-based malware targeting European victims.
- Use of `.xll` likely chosen to evade traditional macro-based detections and sandbox triggers.

**Behavioral Tags:** #payload_delivery #europe_targeting #xll_malware #phishing_ops