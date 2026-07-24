from __future__ import annotations

import struct
from pathlib import Path


class MachOError(Exception):
    pass


MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19


def read_macho_blob(path: str | Path) -> memoryview:
    data = memoryview(Path(path).read_bytes())

    if len(data) < 32:
        raise MachOError("Truncated Mach-O file")

    magic = struct.unpack_from("<I", data, 0)[0]

    if magic != MH_MAGIC_64:
        raise MachOError("Only 64-bit little-endian Mach-O is supported")

    # mach_header_64:
    # magic      4
    # cputype    4
    # cpusubtype 4
    # filetype   4
    # ncmds      4
    # sizeofcmds 4
    # flags      4
    # reserved   4
    ncmds = struct.unpack_from("<I", data, 16)[0]

    offset = 32

    for _ in range(ncmds):
        if offset + 8 > len(data):
            raise MachOError("Invalid load command")

        cmd, cmdsize = struct.unpack_from("<II", data, offset)

        if cmdsize < 8 or offset + cmdsize > len(data):
            raise MachOError("Invalid load command size")

        if cmd == LC_SEGMENT_64:
            # segment_command_64:
            # cmd       4
            # cmdsize   4
            # segname   16
            # vmaddr    8
            # vmsize    8
            # fileoff   8
            # filesize  8
            segname = bytes(data[offset + 8 : offset + 24]).rstrip(b"\0")

            if segname == b"__POSTJECT":
                fileoff, filesize = struct.unpack_from(
                    "<QQ",
                    data,
                    offset + 40,
                )

                end = fileoff + filesize

                if end > len(data):
                    raise MachOError("POSTJECT segment outside file")

                return data[fileoff:end]

        offset += cmdsize

    raise MachOError("No __POSTJECT segment found")
