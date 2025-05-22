# 🧱 Infrastructure Analysis – Black Basta

This document outlines the infrastructure leveraged by the Black Basta threat group during the timeframe covered in the Matrix logs and correlated OSINT sources. This includes command-and-control (C2) servers, proxy chains, VPNs, malware distribution nodes, and mail infrastructure.

Each entry is annotated with functionality, enrichment, and analyst tags. This file complements `indicators.md` and is meant to support:
- Infrastructure mapping and chaining
- Visual correlation (pivot maps, relationship graphs)
- Detection strategy development

---

## 🕸️ Infrastructure Roles & Functions

### 🔹 Command-and-Control (C2) Servers
These nodes are used to manage bots, payloads, and exfiltration mechanisms.

*Examples:*
- `45.227.254[.]7` – Credentialed access (`root` / `kgb0pBjv1jBF0OzI3pb`)
- `141.98.80[.]158` – Associated with domain `umomrmwa[.]com`

### 🔹 Proxy Infrastructure
Used to mask operational access, bounce signals, and obscure source attribution.

*Examples:*
- `5.8.18[.]230` – Coba proxy, mapped to `rokllold279[.]com`
- `23.81.246[.]14` and `23.81.246[.]165` – Labeled “proxy?” in chat logs

### 🔹 VPN Nodes / Gateways
Suspected intermediary hops for RDP/VNC access or broader pivoting.

*Examples:*
- `88.214.25[.]244` – Labeled VPN
- `179.60.149[.]235` – Possible VPN exit

### 🔹 Malware & Payload Hosting
Short-term or persistent locations used to drop initial access payloads (VBS, EXEs, loaders).

*Examples:*
- `temp.sh` links tied to VBS archives
- `104.200.72[.]124` – Linked to Mail-in-a-Box infra

### 🔹 Analyst-Identified Threat Stack
These nodes represent higher confidence C2/proxy/malware correlation based on behavior, reuse, or OSINT.

| IP / Host             | Role         | Notes / Tags                             |
|-----------------------|--------------|------------------------------------------|
| `147.78.47[.]48`      | CobaltStrike | Netherlands node, likely reused infra    |
| `176.174.149[.]37`    | C2 (DarkGate)| Mentioned in malware deployment chat     |
| `179.60.149[.]5`      | ESXi (?)         | Credentials: `epo / $E14GErufwFBsaf`     |
| `185.244.216[.]102`   | Proxy Bot    | Credentialed, labeled `3APA3A` in logs   |

---

## 🧠 Notes for Analysts
- Some infrastructure appears recycled or leased (e.g. FiveCloud, mnets.net)
- Several nodes appear active and unflagged in public blocklists
- Direct mapping to credentials and behavior found in chat logs
- Tagging syntax (`#c2`, `#proxy`, `#vpn`, `#osint`, `#payload_host`) should match across `indicators.md`

---

## 📍 Enrichment Targets

### Passive DNS & GeoIP Snapshot

| IP Address         | Resolved Domain      | Country       | ASN / Provider         | Status       |
|--------------------|-----------------------|---------------|------------------------|--------------|
| 141.98.80[.]158    | umomrmwa[.]com        | Seychelles    | AS203264 (MivoCloud)   | Active       |
| 45.227.254[.]7     | xavfgrtgrg[.]com      | Russia        | AS210644 (Mirhosting)  | Likely Down  |

---

### Planned Enrichment Items
- Passive DNS history (VirusTotal, RiskIQ, SecurityTrails)
- TLS certs (via Censys or Shodan)
- Autonomous System (AS) attribution for clustering
- GeoIP trends for delivery campaigns

---

## 🔄 Relationship Map (Optional Visual Phase)
When complete, we can transform this markdown into:
- Graph-based maps (using Obsidian, SIERRA, or MermaidJS)
- Relationship diagrams showing tool > server > target flow
- Infrastructure trees (e.g. proxy > C2 > exfil node)

### 🧪 Example: MermaidJS Diagram (Obsidian-Compatible)

```mermaid
graph TD
    Proxy1[23.81.246.14 (Proxy)] --> C2A[141.98.80.158 (C2)]
    Proxy2[5.8.18.230 (Coba Proxy)] --> C2B[45.227.254.7 (C2)]
    C2A --> MailInfra[104.200.72.124 (Mail Host)]
    C2B --> PayloadNode[temp.sh Payload Drop]
    VPN1[88.214.25.244 (VPN)] --> Proxy1
    VPN2[179.60.149.235 (VPN)] --> Proxy2
