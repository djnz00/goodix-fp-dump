from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .archive import ArchiveRun
from .device_info import collect_preflight
from .usb_reset import reset_usb_device


class FirmwareDumpError(RuntimeError):
    pass


def dump_device_firmware(
    *,
    archive: ArchiveRun,
    vendor: int,
    product: int,
    length: int,
    chunk_size: int = 256,
    reset_usb: bool = True,
) -> dict[str, Any]:
    if length <= 0:
        raise ValueError("length must be positive")
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    manifest: dict[str, Any] = {
        "created_at": datetime.now(UTC).isoformat(),
        "operation": "dump-firmware",
        "device": {
            "vendor_id": f"{vendor:04x}",
            "product_id": f"{product:04x}",
        },
        "requested": {
            "length": length,
            "chunk_size": chunk_size,
            "reset_usb": reset_usb,
        },
        "preflight": collect_preflight(
            vendor,
            product,
            command_path="goodix-fp-dump dump-firmware",
            repo_root=Path(__file__).resolve().parents[1],
        ),
    }
    if reset_usb:
        manifest["usb_reset"] = reset_usb_device(vendor, product)

    data = bytearray()
    device = None
    try:
        import goodix
        import protocol

        device = goodix.Device(product, protocol.USBProtocol, timeout=5)
        device.nop()
        manifest["firmware_version"] = device.firmware_version()
        for offset in range(0, length, chunk_size):
            read_len = min(chunk_size, length - offset)
            data.extend(device.read_firmware(offset, read_len))
    except Exception as error:
        manifest["status"] = "error"
        manifest["error"] = {
            "type": type(error).__name__,
            "message": str(error),
            "bytes_read": len(data),
        }
        archive.write_manifest(manifest)
        return manifest
    finally:
        if device is not None:
            try:
                device.disconnect()
            except Exception as error:
                manifest["disconnect_error"] = {
                    "type": type(error).__name__,
                    "message": str(error),
                }

    output = archive.path / "original" / "firmware-read-firmware.bin"
    output.write_bytes(data)
    manifest["status"] = "ok"
    manifest["firmware_dump"] = archive.artifact_record(output)
    archive.write_manifest(manifest)
    return manifest
