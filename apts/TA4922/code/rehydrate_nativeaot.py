#!/usr/bin/env python3
"""This parser implements the command stream used by the analyzed .NET 10
NativeAOT Cruciferra build. It reads bytes only; it does not load or execute
the input PE.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def i32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<i", data, offset)[0]


def parse_pe(data: bytes) -> tuple[int, list[tuple[int, int, int, int]]]:
    if data[:2] != b"MZ":
        raise ValueError("input does not start with an MZ header")
    pe_offset = u32(data, 0x3C)
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("bounded PE signature not found")
    section_count = u16(data, pe_offset + 6)
    optional_size = u16(data, pe_offset + 20)
    optional = pe_offset + 24
    if u16(data, optional) != 0x20B:
        raise ValueError("this reconstruction expects PE32+")
    image_base = struct.unpack_from("<Q", data, optional + 24)[0]
    section_table = optional + optional_size
    sections = []
    for index in range(section_count):
        entry = section_table + index * 40
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, entry + 8
        )
        if raw_offset + raw_size > len(data):
            raise ValueError("PE section exceeds the input file")
        sections.append((rva, virtual_size, raw_offset, raw_size))
    return image_base, sections


def rva_to_raw(
    sections: list[tuple[int, int, int, int]], rva: int
) -> int | None:
    for section_rva, virtual_size, raw_offset, raw_size in sections:
        backed = min(virtual_size, raw_size)
        if section_rva <= rva < section_rva + backed:
            return raw_offset + rva - section_rva
    return None


def decode_command(
    data: bytes, raw_offset: int, raw_end: int
) -> tuple[int, int, int]:
    if raw_offset >= raw_end:
        raise ValueError("missing dehydration command")
    value = data[raw_offset]
    raw_offset += 1
    command = value & 7
    payload = value >> 3
    extra_bytes = payload - 28
    if extra_bytes > 0:
        if extra_bytes > 3 or raw_offset + extra_bytes > raw_end:
            raise ValueError("invalid extended dehydration payload")
        payload = (
            int.from_bytes(
                data[raw_offset : raw_offset + extra_bytes], "little"
            )
            + 28
        )
        raw_offset += extra_bytes
    return raw_offset, command, payload


def rehydrate(
    data: bytes,
    sections: list[tuple[int, int, int, int]],
    image_base: int,
    start_rva: int,
    end_rva: int,
) -> tuple[int, bytes, int, int]:
    if end_rva <= start_rva + 4:
        raise ValueError("invalid dehydrated-data RVA range")
    start_raw = rva_to_raw(sections, start_rva)
    end_raw = rva_to_raw(sections, end_rva - 1)
    if start_raw is None or end_raw is None:
        raise ValueError("dehydrated command stream is not raw-backed")
    destination_rva = start_rva + i32(data, start_raw)
    current_rva = start_rva + 4
    output = bytearray()
    command_count = 0
    max_fixup = -1

    while current_rva < end_rva:
        current_raw = rva_to_raw(sections, current_rva)
        if current_raw is None:
            raise ValueError("command is not raw-backed")
        next_raw, command, payload = decode_command(
            data, current_raw, end_raw + 1
        )
        current_rva += next_raw - current_raw
        command_count += 1

        if command == 0:  # Copy
            source_raw = rva_to_raw(sections, current_rva)
            if source_raw is None or current_rva + payload > end_rva:
                raise ValueError("copy exceeds the dehydration stream")
            output.extend(data[source_raw : source_raw + payload])
            current_rva += payload
        elif command == 1:  # ZeroFill
            output.extend(b"\0" * payload)
        elif command in (2, 3):  # RelPtr32Reloc / PtrReloc
            max_fixup = max(max_fixup, payload)
            destination_cell_rva = destination_rva + len(output)
            fixup_cell_rva = end_rva + payload * 4
            fixup_cell_raw = rva_to_raw(sections, fixup_cell_rva)
            if fixup_cell_raw is None:
                raise ValueError("fixup cell is not raw-backed")
            value_rva = fixup_cell_rva + i32(data, fixup_cell_raw)
            if command == 2:
                output.extend(
                    struct.pack("<i", value_rva - destination_cell_rva)
                )
            else:
                output.extend(struct.pack("<Q", image_base + value_rva))
        elif command in (4, 5):  # InlineRelPtr32Reloc / InlinePtrReloc
            source_size = payload * 4
            source_raw = rva_to_raw(sections, current_rva)
            if source_raw is None or current_rva + source_size > end_rva:
                raise ValueError("inline fixup exceeds the dehydration stream")
            for index in range(payload):
                source_cell_rva = current_rva + index * 4
                value_rva = source_cell_rva + i32(
                    data, source_raw + index * 4
                )
                destination_cell_rva = destination_rva + len(output)
                if command == 4:
                    output.extend(
                        struct.pack("<i", value_rva - destination_cell_rva)
                    )
                else:
                    output.extend(struct.pack("<Q", image_base + value_rva))
            current_rva += source_size
        else:
            raise ValueError(f"unsupported dehydration command {command}")

        if len(output) > 64 * 1024 * 1024:
            raise ValueError("implausibly large hydrated output")

    return destination_rva, bytes(output), command_count, max_fixup


def parse_int(value: str) -> int:
    return int(value, 0)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("--start-rva", required=True, type=parse_int)
    parser.add_argument("--end-rva", required=True, type=parse_int)
    parser.add_argument("--target-rva", type=parse_int)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    data = args.source.read_bytes()
    image_base, sections = parse_pe(data)
    destination_rva, hydrated, command_count, max_fixup = rehydrate(
        data,
        sections,
        image_base,
        args.start_rva,
        args.end_rva,
    )
    result: dict[str, object] = {
        "analysis_mode": "offline byte parser; no PE loading or execution",
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "image_base_hex": f"0x{image_base:x}",
        "stream_start_rva_hex": f"0x{args.start_rva:x}",
        "stream_end_rva_hex": f"0x{args.end_rva:x}",
        "destination_start_rva_hex": f"0x{destination_rva:x}",
        "destination_end_rva_hex": f"0x{destination_rva + len(hydrated):x}",
        "hydrated_size": len(hydrated),
        "hydrated_sha256": hashlib.sha256(hydrated).hexdigest(),
        "command_count": command_count,
        "maximum_fixup_index": max_fixup,
    }

    if args.target_rva is not None:
        relative = args.target_rva - destination_rva
        if relative < 0 or relative + 12 > len(hydrated):
            raise ValueError("target RVA is outside the hydrated output")
        method_table = struct.unpack_from("<Q", hydrated, relative)[0]
        string_length = u32(hydrated, relative + 8)
        string_end = relative + 12 + string_length * 2
        if string_end > len(hydrated):
            raise ValueError("target string exceeds the hydrated output")
        result["target"] = {
            "rva_hex": f"0x{args.target_rva:x}",
            "relative_offset_hex": f"0x{relative:x}",
            "method_table_va_hex": f"0x{method_table:x}",
            "utf16_length": string_length,
            "utf16_value": hydrated[
                relative + 12 : string_end
            ].decode("utf-16le"),
        }

    if args.output is not None:
        args.output.write_bytes(hydrated)
        result["output_path"] = str(args.output)

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
