from __future__ import annotations

import hashlib
import struct
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


@dataclass(frozen=True, slots=True)
class ProductionReadVariant:
    name: str
    parser: str
    description: str


PRODUCTION_SELECTORS = (
    ProductionSelector("production-psk-sgx", 0xBB010002, length=114),
    ProductionSelector("production-psk-hash", 0xBB020001, length=0x20),
    ProductionSelector("production-pmk-hmac", 0xBB020007, length=0x20),
)

PRODUCTION_READ_VARIANTS = (
    ProductionReadVariant(
        "linux-legacy",
        "linux_legacy",
        "current Linux helper layout: length, number, selector, zero",
    ),
    ProductionReadVariant(
        "windows-tlv",
        "windows_tlv",
        "Windows PresetPskReadSpecDataR layout: selector, zero",
    ),
    ProductionReadVariant(
        "windows-tlv-12",
        "windows_tlv",
        "12-byte TLV header allocation variant: selector, zero, zero",
    ),
    ProductionReadVariant(
        "windows-tlv-length",
        "windows_tlv",
        "TLV request with requested length in the third dword",
    ),
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


def probe_production_read_variants(
    *,
    archive: ArchiveRun,
    vendor: int,
    product: int,
    selectors: tuple[ProductionSelector, ...] = PRODUCTION_SELECTORS,
    variants: tuple[ProductionReadVariant, ...] = PRODUCTION_READ_VARIANTS,
    reset_usb: bool = True,
    timeout: float = 5,
) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "created_at": datetime.now(UTC).isoformat(),
        "operation": "read-production-variants",
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
            "variants": [
                {
                    "name": variant.name,
                    "parser": variant.parser,
                    "description": variant.description,
                }
                for variant in variants
            ],
        },
        "preflight": collect_preflight(
            vendor,
            product,
            command_path="goodix-fp-dump read-production-variants",
            repo_root=Path(__file__).resolve().parents[1],
        ),
        "variant_results": [],
    }

    try:
        import goodix
        import protocol

        for selector in selectors:
            for variant in variants:
                manifest["variant_results"].append(
                    _probe_variant_session(
                        archive,
                        goodix,
                        protocol,
                        vendor,
                        product,
                        selector,
                        variant,
                        reset_usb=reset_usb,
                        timeout=timeout,
                    )
                )
        manifest["status"] = (
            "ok"
            if any(item.get("ok") for item in manifest["variant_results"])
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


def _probe_variant_session(
    archive: ArchiveRun,
    goodix: Any,
    protocol: Any,
    vendor: int,
    product: int,
    selector: ProductionSelector,
    variant: ProductionReadVariant,
    *,
    reset_usb: bool,
    timeout: float,
) -> dict[str, Any]:
    record = {
        **_selector_record(selector),
        "variant": {
            "name": variant.name,
            "parser": variant.parser,
            "description": variant.description,
        },
    }
    if reset_usb:
        record["usb_reset"] = reset_usb_device(vendor, product)

    device = None
    try:
        device = goodix.Device(product, protocol.USBProtocol, timeout=timeout)
        device.nop()
        record["firmware_version"] = device.firmware_version()
        record.update(
            _probe_variant(archive, goodix, protocol, device, selector, variant)
        )
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


def _probe_variant(
    archive: ArchiveRun,
    goodix: Any,
    protocol: Any,
    device: Any,
    selector: ProductionSelector,
    variant: ProductionReadVariant,
) -> dict[str, Any]:
    payload = _variant_payload(selector, variant)
    record: dict[str, Any] = {
        "request": {
            "command": f"0x{goodix.COMMAND_PRESET_PSK_READ_R:02x}",
            "payload_length": len(payload),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "driver_output_length": selector.length + 9,
        }
    }

    try:
        response = _send_raw_command(
            goodix,
            protocol,
            device,
            goodix.COMMAND_PRESET_PSK_READ_R,
            payload,
        )
    except Exception as error:
        record["ok"] = False
        record["error"] = {
            "type": type(error).__name__,
            "message": str(error),
        }
        return record

    output = (
        archive.path
        / "original"
        / "production-probes"
        / f"{selector.name}.{variant.name}.response.bin"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(response)

    record["response"] = {
        "length": len(response),
        "artifact": archive.artifact_record(output),
    }
    record.update(_parse_variant_response(response, selector, variant))
    return record


def _variant_payload(
    selector: ProductionSelector,
    variant: ProductionReadVariant,
) -> bytes:
    if variant.name == "linux-legacy":
        return struct.pack(
            "<IIII",
            selector.length,
            selector.number,
            selector.flags,
            0,
        )
    if variant.name == "windows-tlv":
        return struct.pack("<II", selector.flags, 0)
    if variant.name == "windows-tlv-12":
        return struct.pack("<III", selector.flags, 0, 0)
    if variant.name == "windows-tlv-length":
        return struct.pack("<III", selector.flags, 0, selector.length)
    raise ValueError(f"unknown production read variant {variant.name}")


def _send_raw_command(
    goodix: Any,
    protocol: Any,
    device: Any,
    command: int,
    payload: bytes,
) -> bytes:
    device.protocol.write(
        goodix.encode_message_pack(goodix.encode_message_protocol(payload, command))
    )

    if isinstance(device.protocol, protocol.USBProtocol):
        goodix.check_ack(
            goodix.check_message_protocol(
                goodix.check_message_pack(device.protocol.read()),
                goodix.COMMAND_ACK,
            ),
            command,
        )

    return goodix.check_message_protocol(
        goodix.check_message_pack(device.protocol.read()),
        command,
    )


def _parse_variant_response(
    response: bytes,
    selector: ProductionSelector,
    variant: ProductionReadVariant,
) -> dict[str, Any]:
    record: dict[str, Any] = {"ok": False}
    if not response:
        record["parse_error"] = "empty response"
        return record

    status = response[0]
    record["mcu_status"] = f"0x{status:02x}"
    if len(response) > 1:
        record["mcu_status_detail"] = f"0x{response[1]:02x}"
    if status != 0:
        return record

    if variant.parser == "linux_legacy":
        if len(response) < 9:
            record["parse_error"] = "linux legacy response shorter than 9 bytes"
            return record
        returned_flags, payload_length = struct.unpack("<II", response[1:9])
        payload = response[9:]
        record["returned_flags"] = f"0x{returned_flags:08x}"
        record["returned_payload_length"] = payload_length
        record["available_payload_length"] = len(payload)
        record["selector_match"] = returned_flags == selector.flags
        record["ok"] = record["selector_match"] and len(payload) >= payload_length
        return record

    if variant.parser == "windows_tlv":
        if len(response) < 9:
            record["parse_error"] = "Windows TLV response shorter than 9 bytes"
            return record
        returned_type, payload_length = struct.unpack("<II", response[1:9])
        payload = response[9:]
        record["returned_type"] = f"0x{returned_type:08x}"
        record["returned_payload_length"] = payload_length
        record["available_payload_length"] = len(payload)
        record["selector_match"] = returned_type == selector.flags
        record["ok"] = record["selector_match"] and len(payload) >= payload_length
        return record

    record["parse_error"] = f"unknown parser {variant.parser}"
    return record
