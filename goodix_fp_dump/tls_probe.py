from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .archive import ArchiveRun
from .device_info import collect_preflight
from .inprocess_tls import PSKMemoryTLSServer
from .usb_reset import reset_usb_device


def probe_device_tls(
    *,
    archive: ArchiveRun,
    vendor: int,
    product: int,
    psk: bytes,
    reset_usb: bool = True,
    timeout: float = 5,
    max_client_records: int = 8,
) -> dict[str, Any]:
    if not psk:
        raise ValueError("psk must not be empty")
    if max_client_records <= 0:
        raise ValueError("max_client_records must be positive")

    manifest: dict[str, Any] = {
        "created_at": datetime.now(UTC).isoformat(),
        "operation": "tls-probe",
        "device": {
            "vendor_id": f"{vendor:04x}",
            "product_id": f"{product:04x}",
        },
        "requested": {
            "reset_usb": reset_usb,
            "timeout": timeout,
            "max_client_records": max_client_records,
        },
        "psk": {
            "length": len(psk),
            "sha256": hashlib.sha256(psk).hexdigest(),
        },
        "preflight": collect_preflight(
            vendor,
            product,
            command_path="goodix-fp-dump tls-probe",
            repo_root=Path(__file__).resolve().parents[1],
        ),
        "tls_records": [],
    }
    if reset_usb:
        manifest["usb_reset"] = reset_usb_device(vendor, product)

    device = None
    tls_server: PSKMemoryTLSServer | None = None
    transcript_dir = archive.path / "captures" / "tls"
    try:
        import goodix
        import protocol

        tls_server = PSKMemoryTLSServer(psk)
        device = goodix.Device(product, protocol.USBProtocol, timeout=timeout)
        device.nop()
        manifest["firmware_version"] = device.firmware_version()

        client_hello = device.request_tls_connection()
        _record_tls_artifact(
            archive,
            manifest,
            transcript_dir,
            "device-000-request-tls.bin",
            client_hello,
        )
        tls_server.receive_handshake(client_hello)
        _write_pending_server_records(archive, manifest, transcript_dir, device, tls_server)

        for index in range(1, max_client_records + 1):
            if tls_server.complete:
                break
            client_record = goodix.check_message_pack(
                device.protocol.read(timeout=timeout),
                goodix.FLAGS_TRANSPORT_LAYER_SECURITY,
            )
            _record_tls_artifact(
                archive,
                manifest,
                transcript_dir,
                f"device-{index:03d}-tls.bin",
                client_record,
            )
            tls_server.receive_handshake(client_record)
            _write_pending_server_records(
                archive,
                manifest,
                transcript_dir,
                device,
                tls_server,
            )

        manifest["tls_status"] = tls_server.status()
        manifest["status"] = "ok" if tls_server.complete else "incomplete"
    except Exception as error:
        manifest["status"] = "error"
        manifest["error"] = {
            "type": type(error).__name__,
            "message": str(error),
        }
        if tls_server is not None:
            manifest["tls_status"] = tls_server.status()
    finally:
        if device is not None:
            try:
                device.disconnect()
            except Exception as error:
                manifest["disconnect_error"] = {
                    "type": type(error).__name__,
                    "message": str(error),
                }
        archive.write_manifest(manifest)

    return manifest


def _write_pending_server_records(
    archive: ArchiveRun,
    manifest: dict[str, Any],
    transcript_dir: Path,
    device: Any,
    tls_server: PSKMemoryTLSServer,
) -> None:
    import goodix

    server_records = tls_server.bytes_to_device()
    if not server_records:
        return

    sequence = sum(1 for item in manifest["tls_records"] if item["direction"] == "host_to_device")
    _record_tls_artifact(
        archive,
        manifest,
        transcript_dir,
        f"host-{sequence:03d}-tls.bin",
        server_records,
        direction="host_to_device",
    )
    device.protocol.write(
        goodix.encode_message_pack(
            server_records,
            goodix.FLAGS_TRANSPORT_LAYER_SECURITY,
        )
    )


def _record_tls_artifact(
    archive: ArchiveRun,
    manifest: dict[str, Any],
    transcript_dir: Path,
    filename: str,
    data: bytes,
    *,
    direction: str = "device_to_host",
) -> None:
    path = transcript_dir / filename
    path.write_bytes(data)
    record = archive.artifact_record(path)
    record["direction"] = direction
    manifest["tls_records"].append(record)
