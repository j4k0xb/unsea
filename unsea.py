import json
import os
import struct
import sys
from enum import Enum

import lief


class SeaFlags(Enum):
    kDefault = 0
    kDisableExperimentalSeaWarning = 1 << 0
    kUseSnapshot = 1 << 1
    kUseCodeCache = 1 << 2
    kIncludeAssets = 1 << 3


class SeaResource:
    def __init__(
        self,
        flags: int,
        code_path: str,
        code: str,
        code_cache: bytes | None,
        assets: dict[str, str] | None,
    ):
        self.flags = flags
        self.code_path = code_path
        self.code = code
        self.code_cache = code_cache
        self.assets = assets

    def create_config(self):
        config = {
            "main": "sea.js",
            "output": "sea.blob",
        }
        if self.flags & SeaFlags.kDisableExperimentalSeaWarning.value:
            config["disableExperimentalSEAWarning"] = True
        if self.flags & SeaFlags.kUseSnapshot.value:
            config["useSnapshot"] = True
        if self.flags & SeaFlags.kUseCodeCache.value:
            config["useCodeCache"] = True
        if self.assets:
            config["assets"] = {
                path: os.path.join("sea_assets", path) for path in self.assets
            }
        return config


class SeaDeserializer:
    def __init__(self, blob: bytes):
        self.blob = blob
        self.offset = 0

    def read_string_view(self) -> str:
        length = self.read_uint64()
        result = self.blob[self.offset : self.offset + length].decode("utf-8")
        self.offset += length
        return result

    def read_uint32(self) -> int:
        result = struct.unpack("<I", self.blob[self.offset : self.offset + 4])[0]
        self.offset += 4
        return result

    def read_uint64(self) -> int:
        result = struct.unpack("<Q", self.blob[self.offset : self.offset + 8])[0]
        self.offset += 8
        return result


def parse_sea(filepath: str) -> SeaResource:
    binary = lief.parse(filepath)

    if lief.is_elf(filepath):
        blob = read_from_elf(binary)
    elif lief.is_pe(filepath):
        blob = read_from_pe(binary)
    elif lief.is_macho(filepath):
        blob = read_from_macho(binary)
    else:
        raise Exception("Unsupported file format")

    deserializer = SeaDeserializer(blob)
    _magic = deserializer.read_uint32()
    flags = deserializer.read_uint32()
    code_path = deserializer.read_string_view()
    code = deserializer.read_string_view()
    code_cache = None
    assets = None

    if flags & SeaFlags.kUseCodeCache.value:
        length = deserializer.read_uint64()
        code_cache = deserializer.blob[
            deserializer.offset : deserializer.offset + length
        ]
        deserializer.offset += length

    if flags & SeaFlags.kIncludeAssets.value:
        assets = {}
        assets_size = deserializer.read_uint64()
        for _ in range(assets_size):
            asset_name = deserializer.read_string_view()
            asset_content = deserializer.read_string_view()
            assets[asset_name] = asset_content

    return SeaResource(flags, code_path, code, code_cache, assets)


def read_from_elf(binary: lief.ELF.Binary) -> bytes:
    for note in binary.notes:
        try:
            if note.name == "NODE_SEA_BLOB\x00":
                return bytes(note.description)
        except UnicodeDecodeError:
            pass
    raise Exception("No NODE_SEA_BLOB found")


def read_from_pe(binary: lief.PE.Binary) -> bytes:
    for directory in binary.resources.childs:
        for child in directory.childs:
            if child.name == "NODE_SEA_BLOB":
                resource_data = next(child.childs)
                return bytes(resource_data.content)
    raise Exception("No NODE_SEA_BLOB found")


def read_from_macho(binary: lief.MachO.Binary) -> bytes:
    postject_segment = binary.get_segment("__POSTJECT")
    if postject_segment is None:
        raise Exception("No __POSTJECT segment found")
    return bytes(postject_segment.content)


def is_safe_path(path: str, safe_dir: str) -> bool:
    return os.path.realpath(path).startswith(os.path.realpath(safe_dir) + os.sep)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python unsea.py <path-to-executable>")
        sys.exit(1)

    sea = parse_sea(sys.argv[1])
    print("Original code path:", sea.code_path)
    print(json.dumps(sea.create_config(), indent=4))

    with open("sea.js", "w") as f:
        f.write(sea.code)

    if sea.code_cache is not None:
        with open("sea.jsc", "wb") as f:
            f.write(sea.code_cache)

    if sea.assets is not None:
        os.mkdir("sea_assets")

        for asset_name, asset_content in sea.assets.items():
            asset_path = os.path.join("sea_assets", asset_name)
            assert is_safe_path(asset_path, "sea_assets"), (
                "Unsafe asset path: " + asset_path
            )
            with open(asset_path, "w") as f:
                f.write(asset_content)
