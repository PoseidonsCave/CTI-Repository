# Technical Analysis

This directory contains analyst-authored technical notes and offline tooling
for the TA4922-corroborated 33863 Cruciferra chain and the technically related
local 119863 image.

## Contents

- [Native and managed code analysis](analysis.md)
- [Container and cryptographic reconstruction](crypto_and_container.md)
- [VenomRAT configuration and protocol](protocol.md)
- [`extract_cruciferra.py`](extract_cruciferra.py) — offline `P`–`_` container
  decoder, parser, and optional custom-ARX decryptor
- [`cruciferra_arx_reference.c`](cruciferra_arx_reference.c) — readable C
  reconstruction of the variant's key schedule and 16-byte stream block
- [`rehydrate_nativeaot.py`](rehydrate_nativeaot.py) — offline reconstruction
  of the .NET 10 NativeAOT dehydrated-data stream used to materialize the
  119863 outer key

## Decompilation Boundary

Ghidra was used to generate entry-point and call-graph-bounded C-like
decompilation sets for both PE-backed DLLs. The raw projects and hundreds of
generated `.c` files remain in the ignored local workbench under
`remnux-output/`. They are neither committed as original source nor
characterized as compilable code. The analysis document identifies the
analytically significant functions and addresses; the C reference file
contains only the reconstructed cryptographic core.

All tools in this directory operate as byte parsers. They do not import, load,
emulate, or execute Windows images. They should be run in an isolated analysis
environment, and all decoded output should be treated as untrusted.

The 119863 key reconstruction is reproducible with:

```sh
python3 rehydrate_nativeaot.py Secur32.mapped.dll \
  --start-rva 0x1102c0 --end-rva 0x12e6d3 --target-rva 0x172478
```

Source files in this directory are covered by the directory-local Apache-2.0
marker in `LICENSE`.
