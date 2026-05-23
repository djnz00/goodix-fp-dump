from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from .archive import ArchiveRun
from .device_info import collect_preflight


def parse_int(value: str) -> int:
    return int(value, 0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="goodix-fp-dump")
    subparsers = parser.add_subparsers(dest="command", required=True)

    preflight = subparsers.add_parser(
        "preflight",
        help="record read-only host and USB state",
    )
    preflight.add_argument("--vendor", type=parse_int, default=0x27C6)
    preflight.add_argument("--product", type=parse_int, required=True)
    preflight.add_argument("--arc", type=Path, default=Path("../arc"))

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "preflight":
        archive = ArchiveRun.create(args.arc, args.vendor, args.product)
        manifest = {
            "created_at": datetime.now(UTC).isoformat(),
            "operation": "preflight",
            "device": {
                "vendor_id": f"{args.vendor:04x}",
                "product_id": f"{args.product:04x}",
            },
            "preflight": collect_preflight(
                args.vendor,
                args.product,
                command_path="run_521d.py -> driver_52xd.py -> protocol.USBProtocol",
                repo_root=Path(__file__).resolve().parents[1],
            ),
        }
        archive.write_manifest(manifest)
        print(json.dumps({"manifest": str(archive.manifest_path)}, sort_keys=True))
        return 0

    raise AssertionError(f"unhandled command {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
