# 📌 Indicators of Compromise (IOCs) – Black Basta

This file contains curated, enriched indicators extracted from Matrix communications and related intelligence during the Black Basta case study. Each entry includes context, relevance, and associated behaviors. Indicators are defanged for safety and correlation.

---

## 🌐 Domains

| Domain                   | Context                      | Tags                     |
|--------------------------|-------------------------------|--------------------------|
| miratechgroup[.]com      | Possible victim infrastructure | #recon #targeting        |
| nbetshopkipstri[.]com    | Possible C2 Server             | #c2 #infrastructure       |

(Additional domains from IP-resolved infrastructure will be added in the corresponding sections below.)

---

## 🧠 Behavioral Tags (Examples Across Indicators)

- `#c2`
- `#vpn`
- `#ftp`
- `#esxi`
- `#onion`
- `#malware_analysis`
- `#proxy_infra`
- `#victim_host`

---

## 🔐 Onion URLs

| URL (Defanged) | Context |
|----------------|---------|
| `stniiomyjliimcg[...]onion` | Possible blog / staging site |
| `bpeln2aqs66qq[...]onion`  | Undisclosed panel or channel |
| `mo2oqqbpemfruv[...]onion` | Includes user/pass combo      |
| `orders44vz5yl7[...]onion` | Unknown (likely shop/panel)   |

---

## 🌍 IP Addresses

| IP Address          | Role / Context                  | Domain (if known)         | Tags                |
|---------------------|----------------------------------|----------------------------|---------------------|
| 5.8.18[.]230        | Proxy (?)                     | rokllold279[.]com          | #proxy #coba        |
| 5.188.87[.]58       | Unspecified                      | -                          | #infrastructure     |
| 5.188.206[.]50      | C2 server                        | -                          | #c2 #root           |
| 23.81.246[.]14      | Proxy (?)                        | -                          | #proxy              |
| 23.81.246[.]165     | Proxy (?)                        | -                          | #proxy              |
| 45.227.254[.]7      | C2 server                        | -                          | #c2 #root           |
| 45.227.252[.]244    | C2 server                        | xavfgrtgrg[.]com           | #c2 #root           |
| 45.227.252[.]246    | C2 server                        | -                          | #c2 #root           |
| 46.161.27[.]152     | C2 server                        | lkcagar[.]com              | #c2 #root           |
| 78.128.113[.]102    | C2 server                        | -                          | #c2 #root           |
| 83.242.96[.]30      | Possible FTP server              | -                          | #ftp                |
| 88.214.25[.]242     | Possible C2 server               | shopttkoltrok[.]com        | #c2 #root           |
| 88.214.25[.]244     | VPN server (?)                   | -                          | #vpn                |
| 88.214.25[.]250     | Possible C2 server               | rokllofrold29[.]com        | #c2 #root           |
| 88.214.26[.]31      | Possible C2 server               | tsvsnjv[.]com              | #c2 #root           |
| 88.214.26[.]33      | Active node, Bulgaria            | fivecloud[.]net            | #proxy #active      |
| 91.238.181[.]250    | Possible C2 server               | xaracc556[.]com            | #c2 #root           |
| 92.118.36[.]203     | C2 server                        | jmvummtu333[.]com          | #c2 #root           |
| 91.191.209[.]70     | C2 server                        | -                          | #c2 #root           |
| 91.191.209[.]110    | Possible C2 server               | -                          | #c2                 |
| 94.228.169[.]123    | C2 server                        | -                          | #c2 #root           |
| 94.228.169[.]143    | RDP bot                          | -                          | #rdp #administrator |
| 104.200.72[.]124    | Mail server (Mail-in-a-Box)      | mailinabox[.]email         | #mail               |
| 141.98.80[.]158     | C2 server                        | umomrmwa[.]com             | #c2 #root           |
| 141.98.81[.]48      | C2 server                        | -                          | #c2 #root           |
| 141.98.9[.]152      | C2 server                        | -                          | #c2 #root           |
| 147.78.47[.]48      | Active server, Netherlands       | mnets[.]net                | #c2 #active         |
| 149.248.76[.]130    | Likely C2 server                 | -                          | #c2                 |
| 176.174.149[.]37    | C2 server (DarkGate reference)   | -                          | #c2 #darkgate       |
| 178.236.247[.]73    | C2 server                        | -                          | #c2 #root           |
| 179.60.149[.]5      | ESXi Server                      | -                          | #esxi #epo          |
| 179.60.149[.]10     | C2 Server                        | -                          | #c2 #root           |
| 179.60.149[.]241    | C2 Server                        | -                          | #c2 #admin          |
| 179.60.149[.]243    | C2 Server                        | -                          | #c2 #root           |
| 179.60.149[.]244    | C2 Server                        | zzerxc[.]com               | #c2 #root           |
| 179.60.149[.]235    | VPN Server (?)                   | -                          | #vpn                |
| 185.244.216[.]102   | C2 / Proxy bot                   | -                          | #c2 #proxy          |
| 194.165.17[.]9      | C2 server                        | -                          | #c2 #root           |
| 194.165.16[.]55     | Possible C2 server               | -                          | #c2                 |
| 194.165.16[.]16     | Possible C2 server               | -                          | #c2 #root           |



Each IP address entry is enriched with:
- Server purpose and function
- Domains (if available)
- OSINT status (e.g., "still active")
- Server usernames/passwords (if recovered)

---

## 🛠 Tooling / Malware References

| Tool / Resource | Context |
|------------------|---------|
| Temp.SH          | Temporary file sharing used for payloads |
| Hybrid Analysis  | Used to baseline DarkGate sample behavior |
| Tria.ge          | Analysis of obfuscated loader             |
| ProxyTraff       | Premium proxy provider                   |
| Random_C2_Profile| Custom Cobalt Strike profiles             |

---

## 🧠 Behavioral Analytics

This section consolidates notable tactics, reconnaissance patterns, and analyst-verified behavior observed across infrastructure and payload staging.

- Monitoring presence across OSINT feeds (e.g., VirusTotal, MalwareBazaar)
- Checking VBS payloads in sandbox environments (Hybrid Analysis, Tria.ge)
- Leveraging random profile generation for Cobalt Strike beacons
- Usage of temporary file sharing infrastructure (Temp.SH)
- Division of actor duties between reconnaissance, staging, and distribution

See `timeline.md` and `infrastructure.md` for extended reference, indicators, and case-linked detections.
