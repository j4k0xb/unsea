from __future__ import annotations

import json
import re
import shutil
import struct
from dataclasses import dataclass
from enum import Flag, IntEnum
from pathlib import Path

from unsea.elf import read_elf_blob
from unsea.macho import read_macho_blob
from unsea.pe import read_pe_blob

MAGIC = 0x143DA20


class SeaParserError(Exception):
    pass


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
    supports_flags: bool
    supports_serializer: bool
    supports_code_path: bool
    supports_code_cache: bool
    supports_assets: bool
    supports_exec_argv_extension: bool
    supports_main_format: bool


@dataclass(frozen=True)
class SeaHeader:
    flags: SeaFlags
    exec_argv_extension: SeaExecArgvExtension
    main_code_format: ModuleFormat


@dataclass(frozen=True)
class SeaResource:
    header: SeaHeader
    code_path: str
    code: memoryview | None
    snapshot: memoryview | None
    code_cache: memoryview | None
    assets: dict[str, memoryview]
    exec_argv: list[str]


class SeaDeserializer:
    def __init__(self, mem: memoryview) -> None:
        self.mem = mem
        self.offset = 0

    def _read(self, size: int) -> memoryview:
        if self.offset + size > len(self.mem):
            raise ValueError(
                f"Attempt to read beyond end of memory: {self.offset + size} > {len(self.mem)}"
            )

        start = self.offset
        self.offset += size
        return self.mem[start : self.offset]

    def read_bytes(self) -> memoryview:
        length = self.read_uint64()
        return self._read(length)

    def read_string(self) -> str:
        return bytes(self.read_bytes()).decode("utf-8")

    def read_uint8(self) -> int:
        result = self._read(1)[0]
        return result

    def read_uint32(self) -> int:
        result = struct.unpack("<I", self._read(4))[0]
        return result

    def read_uint64(self) -> int:
        result = struct.unpack("<Q", self._read(8))[0]
        return result


def parse_assets(deserializer: SeaDeserializer) -> dict[str, memoryview]:
    assets = {}
    assets_size = deserializer.read_uint64()
    for _ in range(assets_size):
        asset_name = deserializer.read_string()
        asset_content = deserializer.read_bytes()
        assets[asset_name] = asset_content
    return assets


def parse_exec_argv(deserializer: SeaDeserializer) -> list[str]:
    exec_argv = []
    exec_argv_size = deserializer.read_uint64()
    for _ in range(exec_argv_size):
        arg = deserializer.read_string()
        exec_argv.append(arg)
    return exec_argv


def parse_header(d: SeaDeserializer, fmt: SeaFormat) -> SeaHeader:
    magic = d.read_uint32()
    if magic != MAGIC:
        raise SeaParserError(f"Invalid SEA magic: {magic}")

    flags = SeaFlags(d.read_uint32()) if fmt.supports_flags else SeaFlags.kDefault

    exec_argv_extension = (
        SeaExecArgvExtension(d.read_uint8())
        if fmt.supports_exec_argv_extension
        else SeaExecArgvExtension.kEnv
    )

    main_code_format = (
        ModuleFormat(d.read_uint8())
        if fmt.supports_main_format
        else ModuleFormat.kCommonJS
    )

    return SeaHeader(
        flags=flags,
        exec_argv_extension=exec_argv_extension,
        main_code_format=main_code_format,
    )


def detect_sea_format(executable: bytes) -> SeaFormat:
    m = re.search(
        rb"https:\/\/nodejs\.org/download/release/v(\d+)\.(\d+)\.(\d+)/", executable
    )
    if not m:
        raise ValueError("Node.js version not found")

    version = tuple(map(int, m.groups()))

    return SeaFormat(
        supports_flags=version >= (20, 2, 0),
        supports_serializer=version >= (20, 3, 0),
        supports_code_path=version >= (20, 6, 0),
        supports_code_cache=version >= (20, 6, 0),
        supports_assets=version >= (20, 12, 0),
        supports_exec_argv_extension=version >= (22, 20, 0),
        supports_main_format=version >= (26, 0, 0),
    )


def parse_sea(filepath: str) -> SeaResource:
    executable = Path(filepath).read_bytes()
    if executable[:4] == b"\x7fELF":
        blob = read_elf_blob(filepath)
    elif executable[:2] == b"MZ":
        blob = read_pe_blob(filepath)
    elif executable[:4] == b"\xcf\xfa\xed\xfe":
        blob = read_macho_blob(filepath)
    else:
        raise SeaParserError("Unsupported file format")

    fmt = detect_sea_format(executable)
    deserializer = SeaDeserializer(blob)
    header = parse_header(deserializer, fmt)

    code_path = deserializer.read_string() if fmt.supports_code_path else "main.js"

    code = (
        (
            deserializer.read_bytes()
            if SeaFlags.kUseSnapshot not in header.flags
            else None
        )
        if fmt.supports_serializer
        else blob[deserializer.offset :]
    )

    snapshot = (
        deserializer.read_bytes() if SeaFlags.kUseSnapshot in header.flags else None
    )

    code_cache = (
        deserializer.read_bytes() if SeaFlags.kUseCodeCache in header.flags else None
    )

    assets = (
        parse_assets(deserializer) if SeaFlags.kIncludeAssets in header.flags else {}
    )

    exec_argv = (
        parse_exec_argv(deserializer)
        if SeaFlags.kIncludeExecArgv in header.flags
        else []
    )

    return SeaResource(
        header=header,
        code_path=code_path,
        code=code,
        snapshot=snapshot,
        code_cache=code_cache,
        assets=assets,
        exec_argv=exec_argv,
    )


def create_config(resource: SeaResource) -> dict:
    config = {}
    config["main"] = "main.js"

    # Default: "commonjs", options: "commonjs", "module"
    # Node.js >= v26.0.0
    if resource.header.main_code_format == ModuleFormat.kModule:
        config["mainFormat"] = "module"

    # --build-sea (Node.js>=v26.0.0): build executable directly
    # --experimental-sea-config: dump preparation blob
    config["output"] = "sea-prep.blob"

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
    if resource.header.exec_argv_extension != SeaExecArgvExtension.kEnv:
        config["execArgvExtension"] = {
            SeaExecArgvExtension.kNone: "none",
            SeaExecArgvExtension.kCli: "cli",
        }[resource.header.exec_argv_extension]

    # Optional
    if resource.assets:
        config["assets"] = {
            path: str(Path("assets") / path) for path in resource.assets
        }

    return config


def is_safe_path(path: Path, safe_dir: Path) -> bool:
    return path.resolve().is_relative_to(safe_dir.resolve())


def prepare_output_dir(output_dir: Path, force: bool) -> None:
    if output_dir.exists():
        if not output_dir.is_dir():
            raise FileExistsError(
                f"Output path exists and is not a directory: {output_dir}"
            )
        if force:
            shutil.rmtree(output_dir)
        elif any(output_dir.iterdir()):
            raise FileExistsError(
                f"Output directory already exists and is not empty: {output_dir}. "
                "Use --force to overwrite it."
            )
    output_dir.mkdir(parents=True, exist_ok=True)


def write_outputs(sea: SeaResource, output_dir: str, force: bool = False) -> None:
    output_path = Path(output_dir)
    prepare_output_dir(output_path, force)
    asset_dir = output_path / "assets"

    with (output_path / "config.json").open("w") as f:
        json.dump(create_config(sea), f, indent=4)

    if sea.code is not None:
        (output_path / "main.js").write_bytes(sea.code)

    if sea.code_cache is not None:
        (output_path / "main.jsc").write_bytes(sea.code_cache)

    if sea.snapshot is not None:
        (output_path / "main-snapshot.bin").write_bytes(sea.snapshot)

    for asset_name, asset_content in sea.assets.items():
        asset_path = asset_dir / asset_name
        if not is_safe_path(asset_path, output_path):
            raise ValueError("Unsafe asset path: " + str(asset_path))

        asset_path.parent.mkdir(parents=True, exist_ok=True)
        asset_path.write_bytes(asset_content)

    print(f"Successfully extracted to '{output_path}'")
