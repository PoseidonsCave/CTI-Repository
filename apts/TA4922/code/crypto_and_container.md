# Container and Cryptographic Reconstruction

## `P`–`_` Base16 Encoding

Both DLLs contain an extended byte sequence in `.reloc` whose values are
restricted to ASCII `P` through `_` (`0x50`–`0x5f`). Each byte represents its
low nibble:

```text
P Q R S T U V W X Y Z [ \ ] ^ _
0 1 2 3 4 5 6 7 8 9 A B C D E F
```

For each pair:

```text
decoded = ((first & 0x0f) << 4) | (second & 0x0f)
```

The framing immediately before the encoded sequence is:

```text
ASCII marker | uint32_le encoded_length | encoded_bytes
```

| Build | Marker | Marker offset | Encoded offset | Encoded length | Decoded SHA-256 |
| --- | --- | ---: | ---: | ---: | --- |
| 33863 | `SetOdgovorila` | `0x188a00` | `0x188a11` | 6,808,302 | `73824a5b8fc030d0de7feaaf0c515db889a87ed3b91b5b9812cedd791f4bbf14` |
| 119863 | `ShinBijesa` | `0x162000` | `0x16200e` | 6,808,296 | `e25f410d567c3f648e0998efcbc19ac91b97713cc29490230aaf1e66b74c5fa5` |

## Decoded Dictionary

The decoded grammar is:

```text
uint32_le entry_count
repeat entry_count times:
    dotnet_7bit_uint utf8_name_length
    byte[utf8_name_length] name
    uint32_le value_length
    byte[value_length] encrypted_value
```

| Build | Entry | Value offset | Length |
| --- | --- | ---: | ---: |
| 33863 | `GetNačini` | `0x13` | 3,386,368 |
| 33863 | `ČariImeStojite` | `0x33ac27` | 17,744 |
| 119863 | `MračnomInfo` | `0x15` | 3,386,368 |
| 119863 | `GetSigurne` | `0x33ac24` | 17,744 |

The stream counter resets to zero for each dictionary value. Consequently,
the two values within a build reuse their initial keystream. Their ciphertext
prefixes therefore expose the XOR of the corresponding plaintext prefixes.

## 33863 Outer Key

The loader's fixed UTF-16LE Base64 key object is at VA `0x180171450`, raw
offset `0x16fc50`:

```text
s48HMc+v1q2wm3p6ZtUiYNqAe9XKkFeoCBwm3jQIW+OoqVA6qJjI/GxNtFyWQqlT
```

Decoded bytes:

```text
b38f0731cfafd6adb09b7a7a66d52260
da807bd5ca9057a8081c26de34085be3
a8a9503aa898c8fc6c4db45c9642a953
```

Decoded-key SHA-256:

```text
140d1e6cec277fa2de46b890acc361fe583c153fbdaa55da6be6f51396307102
```

This key is fixed in the 33863 build. It must not be treated as a universal
Cruciferra or TA4922 key.

## Key Expansion

Treat the first 32 key bytes as eight little-endian `uint32_t` words. Expand
to 24 words:

```text
for i = 8..23:
    left  = rol32(w[i-1], 5) ^ w[i-7]
    right = (i * 0x9e3779b9) ^ w[i-8]
    w[i]  = left + right mod 2^32
```

The final 16 key bytes seed four state words.

## Stream Block

For zero-based block counter `block_index`:

```text
a = tail[0] ^ block_index
b = tail[1] ^ ~block_index
c = tail[2] ^ 0x6a09e667
d = tail[3] ^ 0xbb67ae85
```

For each of the 24 expanded schedule words:

```text
a += b; d = rol32(d ^ a, 16)
c += d; b = rol32(b ^ c, 12)
a += b; d = rol32(d ^ a, 8)
c += d; b = rol32(b ^ c, 7)
a ^= schedule_word
```

Serialize `a,b,c,d` little-endian and XOR with the ciphertext. The sequence
resembles a ChaCha quarter round, but the state layout, schedule injection,
constants, and round construction are custom. The appropriate descriptor is
**custom 24-round ChaCha-like ARX stream transform**.

## 119863 NativeAOT Key Recovery

The 119863 decryptor reads a managed string object at VA `0x180172478`;
however, that address falls within the virtual, non-file-backed portion of
`.data`. This placement explains why 936 direct Base64-window tests did not
locate the key.

The image's ReadyToRun header identifies:

```text
type 206 FrozenObjectRegion  0x180162b48-0x180173bd0
type 207 DehydratedData      0x1801102c0-0x18012e6d3
```

Static disassembly of the image's embedded rehydration routine at
`0x180036660` established the command grammar: `Copy`, `ZeroFill`,
32-bit-relative and absolute pointer relocations, plus inline forms. The
analyst-authored `rehydrate_nativeaot.py` parser reconstructed 229,760 bytes
at RVA `0x160ee0-0x199060`. The target object contains a 64-character UTF-16
string:

```text
yew5kW3JeeA0VwtY64gP3vSjpGBSFBg3rd6p/PyiMRrBU1uTx68FQEf/4plE0a2A
```

Decoded-key SHA-256:

```text
e2e0be60905e89b8936285876ed0bcc9202525686ec91888022ed3cf90585976
```

Applying this key with the independently reconstructed ARX transform yielded:

| Entry | Plaintext SHA-256 | Result |
| --- | --- | --- |
| `MračnomInfo` | `fbeb3ab69d49c15b18e7c3024c5ed76d0a93442df3e62805d6d352cab73885dd` | Byte-identical to the 3,386,368-byte managed 33863 client |
| `GetSigurne` | `07c5209bf83065fe760f4fee4ed2308b0c523671f68ca73a3854c2c8c28c0541` | Byte-identical to the 17,744-byte 33863 `ardrv.sys` |

The earlier ciphertext-XOR result is therefore independently validated rather
than inferred solely from the ciphertext relationship. This recovery was
entirely static: no PE, initializer, or managed method was loaded or executed.

## Distinct Client Configuration Cryptography

The managed payload uses a separate scheme and key:

- Base64 key:
  `UkZra1ZzVmVweVFxM2tIUXRJY21OZHhZQ0JPdWFsTWI=`
- decoded key: `RFkkVsVepyQq3kHQtIcmNdxYCBOualMb`
- PBKDF2-HMAC-SHA1, salt `VenomRATByVenom`, 50,000 iterations,
  96 derived bytes
- AES key: first 32 derived bytes
- HMAC key: remaining 64 bytes
- record:
  `HMAC-SHA256(IV || ciphertext)[32] || IV[16] || AES-256-CBC ciphertext`

Every recovered setting passed HMAC verification before decryption. This
key must not be conflated with the outer Cruciferra ARX key.
