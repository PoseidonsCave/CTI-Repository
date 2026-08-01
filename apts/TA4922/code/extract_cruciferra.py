#!/usr/bin/env python3
"""Offline decoder/parser for the Cruciferra P-_ stage container.

This tool reads PE bytes only. It does not import, load,
emulate, or execute the examined Windows image. If a 48-byte Base64 key is
provided, it applies the custom ARX transform reconstructed from the local
Cruciferra variants. That transform is not standard ChaCha.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import struct
import unicodedata
from pathlib import Path
from typing import BinaryIO

try:
    import numpy as np
except ImportError:  # Portable fallback; bulk decryption is slower without NumPy.
    np = None


MASK32 = 0xFFFFFFFF
MIN_ENCODED_RUN = 1024


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def read_exact(stream: BinaryIO, size: int) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise ValueError(f"short read: wanted {size} bytes, got {len(data)}")
    return data


def parse_pe_sections(path: Path) -> list[dict[str, int | str]]:
    """Return bounded PE section metadata without loading the image."""

    with path.open("rb") as stream:
        dos = read_exact(stream, 0x40)
        if dos[:2] != b"MZ":
            raise ValueError("input does not start with an MZ header")
        pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
        stream.seek(pe_offset)
        coff = read_exact(stream, 24)
        if coff[:4] != b"PE\0\0":
            raise ValueError("bounded PE signature not found")
        section_count = struct.unpack_from("<H", coff, 6)[0]
        optional_size = struct.unpack_from("<H", coff, 20)[0]
        if not 1 <= section_count <= 96:
            raise ValueError(f"implausible section count: {section_count}")
        stream.seek(optional_size, 1)
        sections: list[dict[str, int | str]] = []
        file_size = path.stat().st_size
        for _ in range(section_count):
            header = read_exact(stream, 40)
            name = header[:8].split(b"\0", 1)[0].decode("ascii", errors="replace")
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<IIII", header, 8
            )
            if raw_offset + raw_size > file_size:
                raise ValueError(f"section {name!r} exceeds the file")
            sections.append(
                {
                    "name": name,
                    "virtual_size": virtual_size,
                    "virtual_address": virtual_address,
                    "raw_size": raw_size,
                    "raw_offset": raw_offset,
                }
            )
        return sections


def find_encoded_stage(
    section: bytes, section_raw_offset: int
) -> tuple[int, int, str, bytes]:
    """Find a maximal P-_ run whose preceding u32 equals its length."""

    candidates: list[tuple[int, int]] = []
    index = 0
    while index < len(section):
        if 0x50 <= section[index] <= 0x5F:
            start = index
            while index < len(section) and 0x50 <= section[index] <= 0x5F:
                index += 1
            run_length = index - start
            if run_length >= MIN_ENCODED_RUN and start >= 4:
                declared = struct.unpack_from("<I", section, start - 4)[0]
                if declared == run_length:
                    candidates.append((start, run_length))
        else:
            index += 1
    if not candidates:
        raise ValueError("no length-framed P-_ encoded stage found")

    start, encoded_length = max(candidates, key=lambda item: item[1])
    marker_end = start - 4
    marker_start = marker_end
    while (
        marker_start > 0
        and marker_end - marker_start < 64
        and 0x21 <= section[marker_start - 1] <= 0x7E
    ):
        marker_start -= 1
    marker = section[marker_start:marker_end].decode("ascii", errors="replace")
    return (
        section_raw_offset + marker_start,
        section_raw_offset + start,
        marker,
        section[start : start + encoded_length],
    )


def decode_p_underscore(encoded: bytes) -> bytes:
    if len(encoded) % 2:
        raise ValueError("P-_ encoded length is odd")
    if any(value < 0x50 or value > 0x5F for value in encoded):
        raise ValueError("encoded bytes contain a value outside ASCII P through _")
    return bytes(
        ((encoded[index] & 0x0F) << 4) | (encoded[index + 1] & 0x0F)
        for index in range(0, len(encoded), 2)
    )


def read_7bit_uint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for _ in range(5):
        if offset >= len(data):
            raise ValueError("truncated 7-bit integer")
        current = data[offset]
        offset += 1
        value |= (current & 0x7F) << shift
        if current & 0x80 == 0:
            return value, offset
        shift += 7
    raise ValueError("overlong 7-bit integer")


def parse_dictionary(data: bytes) -> list[dict[str, int | str | bytes]]:
    if len(data) < 4:
        raise ValueError("decoded container lacks an entry count")
    count = struct.unpack_from("<I", data, 0)[0]
    if not 1 <= count <= 1024:
        raise ValueError(f"implausible dictionary entry count: {count}")
    offset = 4
    entries: list[dict[str, int | str | bytes]] = []
    for index in range(count):
        record_offset = offset
        name_size, offset = read_7bit_uint(data, offset)
        name_end = offset + name_size
        if name_end + 4 > len(data):
            raise ValueError(f"entry {index} has a truncated name or value length")
        name = data[offset:name_end].decode("utf-8", errors="strict")
        value_size = struct.unpack_from("<I", data, name_end)[0]
        value_offset = name_end + 4
        value_end = value_offset + value_size
        if value_end > len(data):
            raise ValueError(f"entry {index} exceeds the decoded container")
        entries.append(
            {
                "index": index,
                "record_offset": record_offset,
                "name": name,
                "value_offset": value_offset,
                "value_size": value_size,
                "value": data[value_offset:value_end],
            }
        )
        offset = value_end
    if offset != len(data):
        raise ValueError(f"decoded container has {len(data) - offset} trailing bytes")
    return entries


def rol32(value: int, count: int) -> int:
    value &= MASK32
    return ((value << count) | (value >> (32 - count))) & MASK32


def expand_schedule(key: bytes) -> list[int]:
    if len(key) != 48:
        raise ValueError("the custom transform requires exactly 48 key bytes")
    words = list(struct.unpack_from("<8I", key, 0))
    for index in range(8, 24):
        left = rol32(words[index - 1], 5) ^ words[index - 7]
        right = ((index * 0x9E3779B9) & MASK32) ^ words[index - 8]
        words.append((left + right) & MASK32)
    return words


def keystream_block(
    schedule: list[int], tail: tuple[int, int, int, int], counter: int
) -> bytes:
    word_a = tail[0] ^ counter
    word_b = tail[1] ^ ((~counter) & MASK32)
    word_c = tail[2] ^ 0x6A09E667
    word_d = tail[3] ^ 0xBB67AE85
    for schedule_word in schedule:
        word_a = (word_a + word_b) & MASK32
        word_d = rol32(word_d ^ word_a, 16)
        word_c = (word_c + word_d) & MASK32
        word_b = rol32(word_b ^ word_c, 12)
        word_a = (word_a + word_b) & MASK32
        word_d = rol32(word_d ^ word_a, 8)
        word_c = (word_c + word_d) & MASK32
        word_b = rol32(word_b ^ word_c, 7)
        word_a ^= schedule_word
    return struct.pack("<4I", word_a, word_b, word_c, word_d)


def decrypt_value(ciphertext: bytes, key: bytes) -> bytes:
    schedule = expand_schedule(key)
    tail = struct.unpack_from("<4I", key, 32)
    if np is not None:
        block_count = (len(ciphertext) + 15) // 16
        if block_count == 0:
            return b""
        counters = np.arange(block_count, dtype=np.uint32)
        word_a = counters ^ np.uint32(tail[0])
        word_b = np.bitwise_not(counters) ^ np.uint32(tail[1])
        word_c = np.full(
            block_count, tail[2] ^ 0x6A09E667, dtype=np.uint32
        )
        word_d = np.full(
            block_count, tail[3] ^ 0xBB67AE85, dtype=np.uint32
        )

        def rol_array(values: object, count: int) -> object:
            return (
                values << np.uint32(count)
            ) | (
                values >> np.uint32(32 - count)
            )

        for schedule_word in schedule:
            word_a = word_a + word_b
            word_d = rol_array(word_d ^ word_a, 16)
            word_c = word_c + word_d
            word_b = rol_array(word_b ^ word_c, 12)
            word_a = word_a + word_b
            word_d = rol_array(word_d ^ word_a, 8)
            word_c = word_c + word_d
            word_b = rol_array(word_b ^ word_c, 7)
            word_a ^= np.uint32(schedule_word)

        words = np.empty((block_count, 4), dtype="<u4")
        words[:, 0] = word_a
        words[:, 1] = word_b
        words[:, 2] = word_c
        words[:, 3] = word_d
        stream = words.tobytes()[: len(ciphertext)]
        scalar = keystream_block(schedule, tail, 0)[: min(16, len(ciphertext))]
        if stream[: len(scalar)] != scalar:
            raise ValueError("vectorized stream failed scalar equivalence check")
        return np.bitwise_xor(
            np.frombuffer(ciphertext, dtype=np.uint8),
            np.frombuffer(stream, dtype=np.uint8),
        ).tobytes()

    plaintext = bytearray(len(ciphertext))
    for counter, offset in enumerate(range(0, len(ciphertext), 16)):
        block = ciphertext[offset : offset + 16]
        stream = keystream_block(schedule, tail, counter)
        plaintext[offset : offset + len(block)] = bytes(
            left ^ right for left, right in zip(block, stream)
        )
    return bytes(plaintext)


def safe_name(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    ascii_value = normalized.encode("ascii", errors="ignore").decode("ascii")
    result = "".join(character if character.isalnum() else "_" for character in ascii_value)
    return result.strip("_") or "unnamed"


def inspect_pe_prefix(data: bytes) -> dict[str, int | str] | None:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 26 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return None
    machine, sections = struct.unpack_from("<HH", data, pe_offset + 4)
    optional_magic = struct.unpack_from("<H", data, pe_offset + 24)[0]
    return {
        "format": {0x10B: "PE32", 0x20B: "PE32+"}.get(
            optional_magic, f"unknown-0x{optional_magic:04x}"
        ),
        "machine_hex": f"0x{machine:04x}",
        "section_count": sections,
        "pe_header_offset_hex": f"0x{pe_offset:x}",
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Statically decode a Cruciferra P-_ container from a PE"
    )
    parser.add_argument("input_pe", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument(
        "--key-base64",
        help="optional Base64 text decoding to the build's exact 48-byte ARX key",
    )
    args = parser.parse_args()

    sections = parse_pe_sections(args.input_pe)
    reloc = next((item for item in sections if item["name"] == ".reloc"), None)
    if reloc is None:
        raise ValueError("input PE has no .reloc section")
    with args.input_pe.open("rb") as stream:
        stream.seek(int(reloc["raw_offset"]))
        section_bytes = read_exact(stream, int(reloc["raw_size"]))

    marker_offset, encoded_offset, marker, encoded = find_encoded_stage(
        section_bytes, int(reloc["raw_offset"])
    )
    decoded = decode_p_underscore(encoded)
    entries = parse_dictionary(decoded)
    key = (
        base64.b64decode(args.key_base64, validate=True)
        if args.key_base64 is not None
        else None
    )
    if key is not None and len(key) != 48:
        raise ValueError("--key-base64 must decode to exactly 48 bytes")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    decoded_path = args.output_dir / "container.pminus_.decoded.bin"
    decoded_path.write_bytes(decoded)
    manifest: dict[str, object] = {
        "analysis_mode": "analyst-authored offline parser; no sample execution",
        "input": {
            "path": str(args.input_pe),
            "size": args.input_pe.stat().st_size,
            "sha256": sha256_file(args.input_pe),
        },
        "reloc": {
            "raw_offset_hex": f"0x{int(reloc['raw_offset']):x}",
            "raw_size": int(reloc["raw_size"]),
        },
        "stage": {
            "marker": marker,
            "marker_raw_offset_hex": f"0x{marker_offset:x}",
            "encoded_raw_offset_hex": f"0x{encoded_offset:x}",
            "encoded_size": len(encoded),
            "encoded_sha256": sha256_bytes(encoded),
            "decoded_size": len(decoded),
            "decoded_sha256": sha256_bytes(decoded),
            "decoded_path": str(decoded_path),
        },
        "container": {
            "grammar": (
                "u32le count; repeated .NET 7-bit UTF-8 name length, "
                "name, u32le value length, value"
            ),
            "entry_count": len(entries),
        },
        "key": (
            {
                "classification": "analyst-supplied build key",
                "decoded_size": len(key),
                "decoded_sha256": sha256_bytes(key),
            }
            if key is not None
            else None
        ),
        "cipher": {
            "classification": "custom 24-round ARX stream transform; not standard ChaCha",
            "block_size": 16,
            "rotations": [16, 12, 8, 7],
            "constants_hex": ["0x9e3779b9", "0x6a09e667", "0xbb67ae85"],
            "counter_reset": "zero for each dictionary value",
        },
        "entries": [],
    }

    for entry in entries:
        value = entry.pop("value")
        assert isinstance(value, bytes)
        index = int(entry["index"])
        name = str(entry["name"])
        suffix = "decrypted" if key is not None else "cipher"
        output_path = (
            args.output_dir / f"entry_{index:02d}_{safe_name(name)}.{suffix}.bin"
        )
        output = decrypt_value(value, key) if key is not None else value
        output_path.write_bytes(output)
        manifest["entries"].append(
            {
                **entry,
                "record_offset_hex": f"0x{int(entry['record_offset']):x}",
                "value_offset_hex": f"0x{int(entry['value_offset']):x}",
                "ciphertext_sha256": sha256_bytes(value),
                "output_path": str(output_path),
                "output_sha256": sha256_bytes(output),
                "pe": inspect_pe_prefix(output),
            }
        )

    manifest_path = args.output_dir / "provenance.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
