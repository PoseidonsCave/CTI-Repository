# Threat Intelligence Repository
This repository is built for researchers, analysts, and fellow defenders
working to curate and contribute to threat intelligence and threat
hunting efforts. It is a community-driven project designed to track,
detect, and help prevent compromise by threat actors.

In addition to adversary tracking, this project also focuses on:

* Behavioral analysis of malware families seen in the wild
* Infrastructure mapping (C2s, proxies, phishing delivery)
* IOC curation and enrichment
* Context-driven case files and timeline analysis

Current malware-analysis case files are indexed in
[malware-analysis/index.md](malware-analysis/index.md).

---

## How Can I Contribute?
Reach out via Discord if you are interested in
collaborating.

Direct collaborator or write access may be screened before it is
granted, and submissions will be reviewed before they are merged. That
screening applies to trusted contribution access, not to the public
ability to read or reuse the repository under its published licenses.

---

## Is This Affiliated With a Company?
No. This is an independent, community-maintained project that is not
affiliated with or owned by any commercial entity or employer.

---

## Ethical Use
This repository is published to support defensive research, education,
and collaborative threat-intelligence work. No raw threat actor logs are
hosted, and indicators are sanitized or redacted where appropriate.

This is an ethical-use statement and community norm. It expresses the
intent of the project, but it does not add extra legal restrictions
beyond the licenses described below.

## Licensing
This repository uses a split-license model to match the different kinds
of material it contains.

* The default repository license is `CC BY-SA 4.0`.
* Detection rules, scripts, and other code-like technical artifacts in
  `apts/black_basta/detection_scripts/` and
  `malware-analysis/adaptix-c2/detection_scripts/` are licensed under
  `Apache-2.0`.
* Third-party material, if any, remains under its original terms.

See [LICENSE](LICENSE), [LICENSING.md](LICENSING.md), and
[LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt).

## Long Term Plan
* Markdown compatibility with Obsidian Notes. This has already started.
* Completely translate and map Black Basta ransomware group
  infrastructure based on Matrix chat logs.
* Create detection opportunities for Black Basta indicators.
