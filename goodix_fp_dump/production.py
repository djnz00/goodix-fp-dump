from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .archive import ArchiveRun
from .device_info import collect_preflight
from .usb_reset import reset_usb_device


@dataclass(frozen=True, slots=True)
class ProductionSelector:
    name: str
    flags: int
    length: int = 0x400
    number: int = 0


PRODUCTION_SELECTORS = (
    ProductionSelector("production-psk-sgx", 0xBB010002, length=114),
    ProductionSelector("production-psk-hash", 0xBB020001, length=0x20),
    ProductionSelector("production-pmk-hmac", 0xBB020007, length=0x20),
)


def read_production_data(
    *,
    archive: ArchiveRun,
    vendor: int,
    product: int,
    selectors: tuple[ProductionSelector, ...] = PRODUCTION_SELECTORS,
    reset_usb: bool = True,
    timeout: float = 5,
) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "created_at": datetime.now(UTC).isoformat(),
        "operation": "read-production-data",
        "device": {
            "vendor_id": f"{vendor:04x}",
            "product_id": f"{product:04x}",
        },
        "requested": {
            "reset_usb": reset_usb,
            "selectors": [
                {
                    "name": selector.name,
                    "flags": f"0x{selector.flags:08x}",
                    "length": selector.length,
                    "number": selector.number,
                }
                for selector in selectors
            ],
        },
        "preflight": collect_preflight(
            vendor,
            product,
            command_path="goodix-fp-dump read-production-data",
            repo_root=Path(__file__).resolve().parents[1],
        ),
        "production_data": [],
    }

    try:
        import goodix
        import protocol

        for selector in selectors:
            manifest["production_data"].append(
                _read_selector_session(
                    archive,
                    goodix,
                    protocol,
                    vendor,
                    product,
                    selector,
                    reset_usb=reset_usb,
                    timeout=timeout,
                )
            )
        manifest["status"] = (
            "ok"
            if all(item.get("ok") for item in manifest["production_data"])
            else "partial"
        )
    except Exception as error:
        manifest["status"] = "error"
        manifest["error"] = {
            "type": type(error).__name__,
            "message": str(error),
        }
    finally:
        archive.write_manifest(manifest)

    return manifest


def _read_selector_session(
    archive: ArchiveRun,
    goodix: Any,
    protocol: Any,
    vendor: int,
    product: int,
    selector: ProductionSelector,
    *,
    reset_usb: bool,
    timeout: float,
) -> dict[str, Any]:
    record = _selector_record(selector)
    if reset_usb:
        record["usb_reset"] = reset_usb_device(vendor, product)

    device = None
    try:
        device = goodix.Device(product, protocol.USBProtocol, timeout=timeout)
        device.nop()
        record["firmware_version"] = device.firmware_version()
        record.update(_read_selector(archive, device, selector))
    except Exception as error:
        record["ok"] = False
        record["error"] = {
            "type": type(error).__name__,
            "message": str(error),
        }
    finally:
        if device is not None:
            try:
                device.disconnect()
            except Exception as error:
                record["disconnect_error"] = {
                    "type": type(error).__name__,
                    "message": str(error),
                }
    return record


def _selector_record(selector: ProductionSelector) -> dict[str, Any]:
    return {
        "name": selector.name,
        "flags": f"0x{selector.flags:08x}",
        "length": selector.length,
        "number": selector.number,
    }


def _read_selector(
    archive: ArchiveRun,
    device: Any,
    selector: ProductionSelector,
) -> dict[str, Any]:
    record = _selector_record(selector)
    try:
        ok, returned_flags, payload = device.preset_psk_read(
            selector.flags,
            selector.length,
            selector.number,
        )
    except Exception as error:
        record["ok"] = False
        record["error"] = {
            "type": type(error).__name__,
            "message": str(error),
        }
        return record

    record["ok"] = bool(ok)
    if returned_flags is not None:
        record["returned_flags"] = f"0x{returned_flags:08x}"
    if payload is not None:
        record["returned_length"] = len(payload)
    if ok and payload is not None:
        output = archive.path / "original" / "production" / f"{selector.name}.bin"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(payload)
        record["artifact"] = archive.artifact_record(output)
    return record
