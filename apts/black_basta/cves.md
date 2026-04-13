# Black Basta Likely Exploited CVEs

This file records likely exploitation paths to prioritize based on the remote-access and edge technologies explicitly referenced in the Black Basta source material. These CVEs are not directly confirmed in the chats. They are practical review leads that fit the technologies in use and the September 2023 through September 2024 time window.

## High-Priority CVEs to Review

| Technology Family | CVE | Why It Matters Here | Priority Window |
| --- | --- | --- | --- |
| Citrix NetScaler ADC / Gateway | `CVE-2023-4966` | Citrix-backed remote access appears in the corpus, and Citrix Bleed was heavily exploited in the same late-2023 period for session theft and edge access | Late 2023 |
| Fortinet FortiOS / FortiProxy SSL-VPN | `CVE-2023-27997` | FortiClient and SSL-VPN tunnel discovery were explicit operator interests, and this Fortinet SSL-VPN flaw aligns with mid-to-late 2023 access operations | 2023 |
| Fortinet FortiOS / FortiProxy SSL-VPN | `CVE-2024-21762` | The 2024 corpus contains validated Fortinet access lists, making this one of the first gateway CVEs to review for exposed Fortinet estates during the same period | Early to mid 2024 |
| Palo Alto PAN-OS GlobalProtect | `CVE-2024-3400` | GlobalProtect registry artifacts were explicitly enumerated in the logs, and this PAN-OS GlobalProtect flaw maps directly to the 2024 timeframe covered by the corpus | 2024 |
| Cisco ASA / FTD WebVPN and AnyConnect-adjacent edge exposure | `CVE-2023-20269` | Cisco AnyConnect usage and Cisco-focused validation appear in the corpus; this is a relevant late-2023 Cisco edge-device path to examine on exposed gateways | Late 2023 |

## How to Use This File

- Treat these CVEs as prioritization leads for retrospective scoping, patch-gap analysis, and exposed-edge review.
- Do not treat them as direct attribution evidence unless separate telemetry confirms exploitation in your environment.
- Where an environment used multiple VPN technologies, review all relevant gateway families rather than assuming a single exploit path.

## Practical Review Steps

1. Inventory whether the environment exposed Citrix, Fortinet, Palo Alto GlobalProtect, or Cisco VPN gateways during the relevant period.
2. Check patch timelines, external exposure, and authentication-log anomalies around the listed CVEs.
3. Correlate successful remote access, session hijacking, password spraying, or validated-credential activity with the same windows.
4. If Fortinet, GlobalProtect, or Citrix infrastructure was internet-exposed and unpatched during those windows, escalate incident scoping even if the initial access path is not yet confirmed.

## Analyst Notes

- The chats strongly support heavy use of enterprise remote-access ecosystems, but they do not consistently state which CVE enabled access to each environment.
- The strongest value of this file is narrowing the likely edge-exploitation review set around technologies actually referenced in the source material.