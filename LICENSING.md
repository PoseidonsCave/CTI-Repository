## Repository Licensing

This repository is intentionally structured so GitHub can detect a single
default license at the repository root while still preserving a more
specific split-license model for different kinds of material.

### Default Repository License

Unless otherwise noted, repository content is licensed under
`CC BY-SA 4.0`.

The root [LICENSE](LICENSE) file is the default license for the
repository's research content, analysis, timelines, IOC curation,
infrastructure mapping, malware-analysis writeups, and similar
documentation.

### Apache-Licensed Technical Artifacts

The following directories are licensed under `Apache-2.0` instead of the
default repository license:

* `apts/black_basta/detection_scripts/`
* `malware-analysis/adaptix-c2/detection_scripts/`

These directories contain detection rules and other code-like technical
artifacts intended for reuse in operational tooling.

The full Apache 2.0 text is available at
[LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt).

### Third-Party Material

Third-party material, if any, remains subject to its original license or
terms.

Raw malware samples, proprietary tools, leaked data, and other third-party
artifacts are not covered by the repository's default license unless they
are explicitly identified as licensed contributions. Analysis notes,
writeups, extracted indicators, and detection content remain governed by
the repository license model described above.

### Ethical Use Statement

The repository's ethical-use language expresses project intent and
community norms. It does not add field-of-use restrictions beyond the
published licenses.
