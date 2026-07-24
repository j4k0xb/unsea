from __future__ import annotations

import struct
from pathlib import Path

PT_NOTE = 4
ELFCLASS32 = 1
ELFCLASS64 = 2


class ELFError(Exception):
    pass


def align4(value: int) -> int:
    return (value + 3) & ~3


def read_elf_blob(path: str | Path) -> bytes:
    data = Path(path).read_bytes()

    if data[:4] != b"\x7fELF":
        raise ELFError("Not an ELF file")

    elf_class = data[4]
    endian = data[5]

    if endian != 1:
        raise ELFError("Only little-endian ELF is supported")

    if elf_class == ELFCLASS64:
        return _read_elf64_notes(data)

    if elf_class == ELFCLASS32:
        return _read_elf32_notes(data)

    raise ELFError("Unknown ELF class")


def _read_notes(data: bytes, offset: int, size: int) -> bytes:
    end = offset + size

    while offset + 12 <= end:
        namesz, descsz, _type = struct.unpack_from("<III", data, offset)
        offset += 12

        if offset + namesz > end:
            raise ELFError("Invalid note name size")

        name = data[offset : offset + namesz]
        offset += align4(namesz)

        if offset + descsz > end:
            raise ELFError("Invalid note description size")

        desc = data[offset : offset + descsz]
        offset += align4(descsz)

        if name.rstrip(b"\0") == b"NODE_SEA_BLOB":
            return desc

    raise ELFError("NODE_SEA_BLOB not found")


def _read_elf64_notes(data: bytes) -> bytes:
    # ELF64 header:
    # e_phoff @ 0x20
    # e_phentsize @ 0x36
    # e_phnum @ 0x38

    phoff = struct.unpack_from("<Q", data, 0x20)[0]
    phentsize = struct.unpack_from("<H", data, 0x36)[0]
    phnum = struct.unpack_from("<H", data, 0x38)[0]

    for i in range(phnum):
        off = phoff + i * phentsize

        p_type = struct.unpack_from("<I", data, off)[0]

        if p_type != PT_NOTE:
            continue

        p_offset = struct.unpack_from("<Q", data, off + 0x08)[0]
        p_filesz = struct.unpack_from("<Q", data, off + 0x20)[0]

        return _read_notes(data, p_offset, p_filesz)

    raise ELFError("No PT_NOTE segment found")


def _read_elf32_notes(data: bytes) -> bytes:
    # ELF32 header:
    # e_phoff @ 0x1c
    # e_phentsize @ 0x2a
    # e_phnum @ 0x2c

    phoff = struct.unpack_from("<I", data, 0x1C)[0]
    phentsize = struct.unpack_from("<H", data, 0x2A)[0]
    phnum = struct.unpack_from("<H", data, 0x2C)[0]

    for i in range(phnum):
        off = phoff + i * phentsize

        p_type = struct.unpack_from("<I", data, off)[0]

        if p_type != PT_NOTE:
            continue

        p_offset = struct.unpack_from("<I", data, off + 0x04)[0]
        p_filesz = struct.unpack_from("<I", data, off + 0x10)[0]

        return _read_notes(data, p_offset, p_filesz)

    raise ELFError("No PT_NOTE segment found")
