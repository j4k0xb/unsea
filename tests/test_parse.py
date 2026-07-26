import platform
import shutil
import subprocess
from pathlib import Path

import pytest

from unsea import create_config, parse_sea

SENTINEL_FUSE = "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2"

PROJECTS_DIR = Path("tests/projects")

NODE_VERSION = (
    subprocess.check_output(["node", "-p", "process.versions.node"]).decode().strip()
)
NODE_VERSION = tuple(map(int, NODE_VERSION.split(".")))


def _generate_sea(cwd: Path) -> Path:
    subprocess.run(
        ["node", "--experimental-sea-config", "sea-config.json"],
        cwd=cwd,
        check=True,
    )
    blob = cwd / "sea-prep.blob"
    assert blob.exists(), "SEA blob was not generated"

    exe_name = "hello.exe" if platform.system() == "Windows" else "hello"
    output_binary = cwd / exe_name

    subprocess.run(
        ["node", "-e", f"require('fs').copyFileSync(process.execPath, '{exe_name}')"],
        cwd=cwd,
        check=True,
    )
    assert output_binary.exists(), "Output binary was not generated"

    npx_cmd = shutil.which("npx.cmd") or shutil.which("npx") or "npx"

    postject_args = [
        npx_cmd,
        "--yes",
        "postject@1.0.0-alpha.6",
        output_binary.name,
        "NODE_SEA_BLOB",
        blob.name,
        "--sentinel-fuse",
        SENTINEL_FUSE,
    ]

    if platform.system() == "Darwin":
        postject_args += ["--macho-segment-name", "NODE_SEA"]

    subprocess.run(postject_args, cwd=cwd, check=True)

    return output_binary


def test_basic() -> None:
    executable = _generate_sea(PROJECTS_DIR / "basic")
    sea = parse_sea(str(executable))
    config = create_config(sea)

    expected_code = (PROJECTS_DIR / "basic" / "main.js").read_bytes()
    assert sea.code == expected_code
    assert config["main"] == "main.js"


@pytest.mark.skipif(
    NODE_VERSION < (20, 12, 0), reason="assets requires Node.js >= 20.12.0"
)
def test_assets() -> None:
    executable = _generate_sea(PROJECTS_DIR / "assets")
    sea = parse_sea(str(executable))

    expected_asset = (PROJECTS_DIR / "assets" / "foo.txt").read_bytes()
    assert bytes(sea.assets["foo.txt"]) == expected_asset


@pytest.mark.skipif(
    NODE_VERSION < (20, 6, 0), reason="codeCache requires Node.js >= 20.6.0"
)
def test_codecache() -> None:
    executable = _generate_sea(PROJECTS_DIR / "codecache")
    sea = parse_sea(str(executable))

    assert sea.code_cache is not None


@pytest.mark.skipif(
    NODE_VERSION < (20, 6, 0), reason="snapshot requires Node.js >= 20.6.0"
)
def test_snapshot() -> None:
    executable = _generate_sea(PROJECTS_DIR / "snapshot")
    sea = parse_sea(str(executable))
    config = create_config(sea)

    assert config["useSnapshot"] is True


@pytest.mark.skipif(
    NODE_VERSION < (22, 20, 0), reason="execArgvExtension requires Node.js >= 22.20.0"
)
def test_exec_argv() -> None:
    executable = _generate_sea(PROJECTS_DIR / "exec-argv")
    sea = parse_sea(str(executable))

    assert sea.exec_argv == ["--no-warnings"]


@pytest.mark.skipif(
    NODE_VERSION < (22, 20, 0), reason="execArgvExtension requires Node.js >= 22.20.0"
)
def test_exec_argv_extension() -> None:
    executable = _generate_sea(PROJECTS_DIR / "exec-argv-extension")
    sea = parse_sea(str(executable))
    config = create_config(sea)

    assert sea.exec_argv == ["--no-warnings"]
    assert config["execArgvExtension"] == "cli"


@pytest.mark.skipif(
    NODE_VERSION < (26, 0, 0), reason="mainFormat requires Node.js >= 26.0.0"
)
def test_esm() -> None:
    executable = _generate_sea(PROJECTS_DIR / "esm")
    sea = parse_sea(str(executable))
    config = create_config(sea)

    assert config["mainFormat"] == "module"
