import json
import os
import shutil
import struct
from dataclasses import dataclass
from enum import Flag, IntEnum

import lief


class SeaFlags(Flag):
    kDefault = 0
    kDisableExperimentalSeaWarning = 1 << 0
    kUseSnapshot = 1 << 1
    kUseCodeCache = 1 << 2
    kIncludeAssets = 1 << 3
    kIncludeExecArgv = 1 << 4


class SeaExecArgvExtension(IntEnum):
    kNone = 0
    kEnv = 1
    kCli = 2


class ModuleFormat(IntEnum):
    kCommonJS = 0
    kModule = 1


@dataclass(frozen=True)
class SeaFormat:
    supports_exec_argv_extension: bool = False
    supports_main_format: bool = False


@dataclass(frozen=True)
class SeaHeader:
    flags: SeaFlags
    exec_argv_extension: SeaExecArgvExtension
    main_code_format: ModuleFormat


@dataclass(frozen=True)
class SeaResource:
    header: SeaHeader
    code_path: str
    code: str
    code_cache: bytes | None
    assets: dict[str, str]
    exec_argv: list[str]


class SeaDeserializer:
    def __init__(self, blob: bytes):
        self.blob = blob
        self.offset = 0

    def read_string_view(self) -> str:
        length = self.read_uint64()
        result = self.blob[self.offset : self.offset + length].decode("utf-8")
        self.offset += length
        return result

    def read_uint8(self) -> int:
        result = self.blob[self.offset]
        self.offset += 1
        return result

    def read_uint32(self) -> int:
        result = struct.unpack("<I", self.blob[self.offset : self.offset + 4])[0]
        self.offset += 4
        return result

    def read_uint64(self) -> int:
        result = struct.unpack("<Q", self.blob[self.offset : self.offset + 8])[0]
        self.offset += 8
        return result


def detect_sea_format(executable: bytes) -> SeaFormat:
    return SeaFormat(
        supports_exec_argv_extension=b'"execArgvExtension" field' in executable,
        supports_main_format=b'"mainFormat" field' in executable,
    )


def parse_code_cache(deserializer: SeaDeserializer) -> bytes:
    length = deserializer.read_uint64()
    code_cache = deserializer.blob[deserializer.offset : deserializer.offset + length]
    deserializer.offset += length
    return code_cache


def parse_assets(deserializer: SeaDeserializer) -> dict[str, str]:
    assets = {}
    assets_size = deserializer.read_uint64()
    for _ in range(assets_size):
        asset_name = deserializer.read_string_view()
        asset_content = deserializer.read_string_view()
        assets[asset_name] = asset_content
    return assets


def parse_exec_argv(deserializer: SeaDeserializer) -> list[str]:
    exec_argv = []
    exec_argv_size = deserializer.read_uint64()
    for _ in range(exec_argv_size):
        arg = deserializer.read_string_view()
        exec_argv.append(arg)
    return exec_argv


def parse_header(deserializer: SeaDeserializer, fmt: SeaFormat) -> SeaHeader:
    _magic = deserializer.read_uint32()
    flags = SeaFlags(deserializer.read_uint32())

    exec_argv_extension = SeaExecArgvExtension.kNone
    if fmt.supports_exec_argv_extension:
        exec_argv_extension = SeaExecArgvExtension(deserializer.read_uint8())

    main_code_format = ModuleFormat.kCommonJS
    if fmt.supports_main_format:
        main_code_format = ModuleFormat(deserializer.read_uint8())

    return SeaHeader(
        flags=flags,
        exec_argv_extension=exec_argv_extension,
        main_code_format=main_code_format,
    )


def parse_sea(filepath: str) -> SeaResource:
    binary = lief.parse(filepath)
    with open(filepath, "rb") as f:
        fmt = detect_sea_format(f.read())
        print(f"SEA format: {fmt}")

    if lief.is_elf(filepath):
        blob = read_elf_blob(binary)
    elif lief.is_pe(filepath):
        blob = read_blob_pe(binary)
    elif lief.is_macho(filepath):
        blob = read_blob_macho(binary)
    else:
        raise Exception("Unsupported file format")

    deserializer = SeaDeserializer(blob)

    header = parse_header(deserializer, fmt)
    print(f"SEA header: {header}")
    code_path = deserializer.read_string_view()
    code = deserializer.read_string_view()

    print(f"Code: {code_path} ({len(code)} bytes)")

    code_cache = None
    if SeaFlags.kUseCodeCache in header.flags:
        code_cache = parse_code_cache(deserializer)
        print(f"Code cache: {len(code_cache)} bytes")

    assets = {}
    if SeaFlags.kIncludeAssets in header.flags:
        assets = parse_assets(deserializer)
        print(f"Assets: {list(assets.keys())}")

    exec_argv = []
    if SeaFlags.kIncludeExecArgv in header.flags:
        exec_argv = parse_exec_argv(deserializer)
        print(f"Execution arguments: {exec_argv}")

    return SeaResource(
        header=header,
        code_path=code_path,
        code=code,
        code_cache=code_cache,
        assets=assets,
        exec_argv=exec_argv,
    )


def read_elf_blob(binary: lief.ELF.Binary) -> bytes:
    for note in binary.notes:
        try:
            if note.name == "NODE_SEA_BLOB\x00":
                return bytes(note.description)
        except UnicodeDecodeError:
            pass
    raise Exception("No NODE_SEA_BLOB found")


def read_blob_pe(binary: lief.PE.Binary) -> bytes:
    for directory in binary.resources.childs:
        for child in directory.childs:
            if child.name == "NODE_SEA_BLOB":
                resource_data = next(child.childs)
                return bytes(resource_data.content)
    raise Exception("No NODE_SEA_BLOB found")


def read_blob_macho(binary: lief.MachO.Binary) -> bytes:
    postject_segment = binary.get_segment("__POSTJECT")
    if postject_segment is None:
        raise Exception("No __POSTJECT segment found")
    return bytes(postject_segment.content)


def create_config(resource: SeaResource) -> dict:
    config = {}
    config["main"] = "main.js"

    #  Default: "commonjs", options: "commonjs", "module"
    # Node.js>=v26.0.0
    if resource.header.main_code_format == ModuleFormat.kModule:
        config["mainFormat"] = "module"

    # --build-sea (Node.js>=v25.5.0): build executable directly
    # --experimental-sea-config: dump preparation blob
    config["output"] = "sea.blob"

    # Default: false
    if SeaFlags.kDisableExperimentalSeaWarning in resource.header.flags:
        config["disableExperimentalSEAWarning"] = True

    # Default: false
    if SeaFlags.kUseSnapshot in resource.header.flags:
        config["useSnapshot"] = True

    # Default: false
    if SeaFlags.kUseCodeCache in resource.header.flags:
        config["useCodeCache"] = True

    # Optional
    if resource.exec_argv:
        config["execArgv"] = resource.exec_argv

    # Default: "env", options: "none", "env", "cli"
    # Node.js>=v25.0.0
    if resource.header.exec_argv_extension != SeaExecArgvExtension.kEnv:
        config["execArgvExtension"] = {
            SeaExecArgvExtension.kNone: "none",
            SeaExecArgvExtension.kCli: "cli",
        }[resource.header.exec_argv_extension]

    # Optional
    if resource.assets:
        config["assets"] = {
            path: os.path.join("assets", path) for path in resource.assets
        }

    return config


def is_safe_path(path: str, safe_dir: str) -> bool:
    return os.path.realpath(path).startswith(os.path.realpath(safe_dir) + os.sep)


def prepare_output_dir(output_dir: str, force: bool) -> None:
    if os.path.exists(output_dir):
        if not os.path.isdir(output_dir):
            raise FileExistsError(
                f"Output path exists and is not a directory: {output_dir}"
            )
        if force:
            shutil.rmtree(output_dir)
        elif os.listdir(output_dir):
            raise FileExistsError(
                f"Output directory already exists and is not empty: {output_dir}. "
                "Use --force to overwrite it."
            )
    os.makedirs(output_dir, exist_ok=True)


def write_outputs(sea: SeaResource, output_dir: str, force: bool = False) -> None:
    prepare_output_dir(output_dir, force)
    asset_dir = os.path.join(output_dir, "assets")
    if sea.assets:
        os.makedirs(asset_dir, exist_ok=True)

    with open(os.path.join(output_dir, "config.json"), "w") as f:
        json.dump(create_config(sea), f, indent=4)

    with open(os.path.join(output_dir, "main.js"), "w") as f:
        f.write(sea.code)

    if sea.code_cache is not None:
        with open(os.path.join(output_dir, "main.jsc"), "wb") as f:
            f.write(sea.code_cache)

    for asset_name, asset_content in sea.assets.items():
        asset_path = os.path.join(asset_dir, asset_name)
        assert is_safe_path(asset_path, output_dir), "Unsafe asset path: " + asset_path
        os.makedirs(os.path.dirname(asset_path), exist_ok=True)
        with open(asset_path, "w") as f:
            f.write(asset_content)

    print(f"Successfully extracted to '{output_dir}'")
