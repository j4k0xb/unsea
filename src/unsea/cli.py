import argparse

from . import parse_sea, write_outputs


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="unsea",
        description=(
            "Extract JavaScript source code and assets from Node "
            "Single Executable Applications"
        ),
    )
    parser.add_argument("executable", help="Path to the SEA executable")
    parser.add_argument(
        "-o",
        "--output",
        help="Directory to write the extracted files to (default: extracted)",
        default="extracted",
    )
    parser.add_argument(
        "-f",
        "--force",
        help="Overwrite output directory if it already exists",
        action="store_true",
    )
    args = parser.parse_args()

    sea = parse_sea(args.executable)
    write_outputs(sea, output_dir=args.output, force=args.force)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
