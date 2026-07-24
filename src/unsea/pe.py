from __future__ import annotations

import struct
from pathlib import Path


class PEError(Exception):
    pass


RT_STRING = 6
RESOURCE_NAME = "NODE_SEA_BLOB"


Section = tuple[int, int, int]


def read_pe_blob(path: str | Path) -> bytes:
    data = Path(path).read_bytes()

    if data[:2] != b"MZ":
        raise PEError("Not a PE file")

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]

    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise PEError("Invalid PE signature")

    coff = pe_offset + 4

    number_of_sections = struct.unpack_from("<H", data, coff + 2)[0]
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]

    optional = coff + 20

    magic = struct.unpack_from("<H", data, optional)[0]

    if magic == 0x20B:  # PE32+
        resource_dir_offset = optional + 128
    elif magic == 0x10B:  # PE32
        resource_dir_offset = optional + 112
    else:
        raise PEError("Unknown PE format")

    resource_rva = struct.unpack_from("<I", data, resource_dir_offset)[0]

    section_table = optional + optional_size

    sections: list[Section] = []

    for i in range(number_of_sections):
        off = section_table + i * 40

        virtual_size, virtual_addr, raw_size, raw_ptr = struct.unpack_from(
            "<IIII", data, off + 8
        )

        sections.append((virtual_addr, max(virtual_size, raw_size), raw_ptr))

    resource_offset = rva_to_offset(
        resource_rva,
        sections,
    )

    return read_resource_tree(data, resource_offset, resource_offset, sections)


def rva_to_offset(rva: int, sections: list[Section]) -> int:
    for va, size, raw in sections:
        if va <= rva < va + size:
            return raw + (rva - va)

    raise PEError(f"Cannot map RVA {rva:#x}")


def read_resource_tree(
    data: bytes,
    base: int,
    directory: int,
    sections: list[Section],
) -> bytes:
    result = _read_resource_tree(data, base, directory, sections)
    if result is None:
        raise PEError("NODE_SEA_BLOB not found")
    return result


def _read_resource_tree(
    data: bytes,
    base: int,
    directory: int,
    sections: list[Section],
) -> bytes | None:
    named, ids = struct.unpack_from(
        "<HH",
        data,
        directory + 12,
    )

    entries = named + ids

    for i in range(entries):
        entry = directory + 16 + i * 8

        name, offset = struct.unpack_from(
            "<II",
            data,
            entry,
        )

        name_is_string = name & 0x80000000
        child_is_dir = offset & 0x80000000

        if name_is_string:
            name_offset = name & 0x7FFFFFFF
            name_length = struct.unpack_from("<H", data, base + name_offset)[0]
            resource_name = data[
                base + name_offset + 2 : base + name_offset + 2 + name_length * 2
            ].decode("utf-16le")

            if resource_name != RESOURCE_NAME:
                continue

            if child_is_dir:
                return read_first_resource_blob(
                    data,
                    base,
                    base + (offset & 0x7FFFFFFF),
                    sections,
                )

            return read_resource_data_entry(
                data,
                base,
                offset & 0x7FFFFFFF,
                sections,
            )

        if child_is_dir:
            result = _read_resource_tree(
                data,
                base,
                base + (offset & 0x7FFFFFFF),
                sections,
            )
            if result is not None:
                return result

    return None


def read_first_resource_blob(
    data: bytes,
    base: int,
    directory: int,
    sections: list[Section],
) -> bytes:
    named, ids = struct.unpack_from(
        "<HH",
        data,
        directory + 12,
    )

    entries = named + ids

    for i in range(entries):
        entry = directory + 16 + i * 8

        _, offset = struct.unpack_from(
            "<II",
            data,
            entry,
        )

        if offset & 0x80000000:
            return read_first_resource_blob(
                data,
                base,
                base + (offset & 0x7FFFFFFF),
                sections,
            )

        return read_resource_data_entry(
            data,
            base,
            offset & 0x7FFFFFFF,
            sections,
        )

    raise PEError("NODE_SEA_BLOB not found")


def read_resource_data_entry(
    data: bytes,
    base: int,
    entry_offset: int,
    sections: list[Section],
) -> bytes:
    data_entry = base + entry_offset

    rva, size = struct.unpack_from(
        "<II",
        data,
        data_entry,
    )

    file_offset = rva_to_offset(
        rva,
        sections,
    )

    return data[file_offset : file_offset + size]
