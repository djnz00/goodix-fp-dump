from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from .archive import ArchiveRun
from .device_info import collect_preflight
from .firmware_dump import dump_device_firmware
from .production import read_production_data
from .tls_probe import probe_device_tls


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

    dump_firmware = subparsers.add_parser(
        "dump-firmware",
        help="attempt a read-only firmware dump through COMMAND_READ_FIRMWARE",
    )
    dump_firmware.add_argument("--vendor", type=parse_int, default=0x27C6)
    dump_firmware.add_argument("--product", type=parse_int, required=True)
    dump_firmware.add_argument("--length", type=parse_int, required=True)
    dump_firmware.add_argument("--chunk-size", type=parse_int, default=256)
    dump_firmware.add_argument("--arc", type=Path, default=Path("../arc"))
    dump_firmware.add_argument("--no-usb-reset", action="store_true")

    tls_probe = subparsers.add_parser(
        "tls-probe",
        help="attempt a read-only in-process TLS-PSK handshake with the device",
    )
    tls_probe.add_argument("--vendor", type=parse_int, default=0x27C6)
    tls_probe.add_argument("--product", type=parse_int, required=True)
    tls_probe.add_argument("--psk-hex", default="00" * 32)
    tls_probe.add_argument("--timeout", type=float, default=5)
    tls_probe.add_argument("--max-client-records", type=int, default=8)
    tls_probe.add_argument("--arc", type=Path, default=Path("../arc"))
    tls_probe.add_argument("--no-usb-reset", action="store_true")

    production_read = subparsers.add_parser(
        "read-production-data",
        help="read PSK/PMK production selectors into the archive",
    )
    production_read.add_argument("--vendor", type=parse_int, default=0x27C6)
    production_read.add_argument("--product", type=parse_int, required=True)
    production_read.add_argument("--timeout", type=float, default=5)
    production_read.add_argument("--arc", type=Path, default=Path("../arc"))
    production_read.add_argument("--no-usb-reset", action="store_true")

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

    if args.command == "dump-firmware":
        archive = ArchiveRun.create(args.arc, args.vendor, args.product)
        manifest = dump_device_firmware(
            archive=archive,
            vendor=args.vendor,
            product=args.product,
            length=args.length,
            chunk_size=args.chunk_size,
            reset_usb=not args.no_usb_reset,
        )
        print(
            json.dumps(
                {
                    "manifest": str(archive.manifest_path),
                    "status": manifest["status"],
                },
                sort_keys=True,
            )
        )
        return 0 if manifest["status"] == "ok" else 2

    if args.command == "tls-probe":
        archive = ArchiveRun.create(args.arc, args.vendor, args.product)
        manifest = probe_device_tls(
            archive=archive,
            vendor=args.vendor,
            product=args.product,
            psk=bytes.fromhex(args.psk_hex),
            reset_usb=not args.no_usb_reset,
            timeout=args.timeout,
            max_client_records=args.max_client_records,
        )
        print(
            json.dumps(
                {
                    "manifest": str(archive.manifest_path),
                    "status": manifest["status"],
                },
                sort_keys=True,
            )
        )
        return 0 if manifest["status"] == "ok" else 2

    if args.command == "read-production-data":
        archive = ArchiveRun.create(args.arc, args.vendor, args.product)
        manifest = read_production_data(
            archive=archive,
            vendor=args.vendor,
            product=args.product,
            reset_usb=not args.no_usb_reset,
            timeout=args.timeout,
        )
        print(
            json.dumps(
                {
                    "manifest": str(archive.manifest_path),
                    "status": manifest["status"],
                },
                sort_keys=True,
            )
        )
        return 0 if manifest["status"] == "ok" else 2

    raise AssertionError(f"unhandled command {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
