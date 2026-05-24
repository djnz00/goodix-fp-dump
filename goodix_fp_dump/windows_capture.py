from __future__ import annotations

import json
import struct
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class TSharkResult:
    fields: tuple[str, ...]
    stdout: str


class CaptureAnalysisError(RuntimeError):
    pass


DESCRIPTOR_FIELDS = (
    "frame.number",
    "frame.time_relative",
    "usb.device_address",
    "usb.idVendor",
    "usb.idProduct",
    "usb.bDescriptorType",
)

DATA_FIELDS = (
    "frame.number",
    "frame.time_relative",
    "usb.device_address",
    "usb.src",
    "usb.dst",
    "usb.endpoint_address",
    "usb.data_len",
    "usb.transfer_type",
    "usbhid.data",
    "usb.data_fragment",
    "usb.capdata",
)

GOODIX_COMMANDS = {
    0x20: "mcu-get-image",
    0xB2: "tls-record",
    0xD0: "request-tls-connection",
    0xE0: "preset-psk-write",
    0xE4: "preset-psk-read",
}


def analyze_capture(
    pcap: Path | str,
    *,
    vendor: int = 0x27C6,
    product: int = 0x521D,
    tshark: str = "tshark",
) -> dict[str, Any]:
    pcap_ = Path(pcap)
    descriptor_rows = parse_rows(
        _run_tshark(
            pcap_,
            fields=DESCRIPTOR_FIELDS,
            display_filter="usb.idVendor || usb.idProduct",
            tshark=tshark,
        )
    )
    data_rows = parse_rows(
        _run_tshark(
            pcap_,
            fields=DATA_FIELDS,
            display_filter=(
                "usb.device_address && "
                "(usb.data_len > 0 || usbhid.data || usb.data_fragment || usb.capdata)"
            ),
            tshark=tshark,
        )
    )

    descriptors = summarize_descriptors(descriptor_rows)
    target_addresses = {
        item["device_address"]
        for item in descriptors
        if item["vendor_id"] == f"{vendor:04x}"
        and item["product_id"] == f"{product:04x}"
    }
    data_summary = summarize_data(data_rows, target_addresses)
    decoded = decode_goodix_payloads(data_rows, target_addresses)
    unattributed_decoded = decode_goodix_payloads(data_rows, None)

    has_target_goodix_messages = bool(decoded["command_counts"])

    return {
        "schema": "goodix-windows-capture-analysis-v1",
        "pcap": str(pcap_),
        "target": {
            "vendor_id": f"{vendor:04x}",
            "product_id": f"{product:04x}",
        },
        "target_present": bool(target_addresses),
        "target_addresses": sorted(target_addresses),
        "valid_for_protocol_analysis": bool(target_addresses and has_target_goodix_messages),
        "descriptors": descriptors,
        "data_summary": data_summary,
        "goodix_messages": decoded,
        "unattributed_goodix_messages": unattributed_decoded,
        "conclusion": _conclusion(
            target_addresses,
            data_summary,
            decoded,
            unattributed_decoded,
            vendor,
            product,
        ),
    }


def write_analysis_report(
    analysis: dict[str, Any],
    *,
    json_path: Path | str,
    markdown_path: Path | str,
) -> None:
    json_path_ = Path(json_path)
    markdown_path_ = Path(markdown_path)
    json_path_.parent.mkdir(parents=True, exist_ok=True)
    markdown_path_.parent.mkdir(parents=True, exist_ok=True)
    json_path_.write_text(json.dumps(analysis, indent=2, sort_keys=True) + "\n")
    markdown_path_.write_text(render_markdown(analysis))


def render_markdown(analysis: dict[str, Any]) -> str:
    target = analysis["target"]
    lines = [
        "# Windows USB Capture Analysis",
        "",
        f"- Capture: `{analysis['pcap']}`",
        f"- Target: `{target['vendor_id']}:{target['product_id']}`",
        f"- Target present in pcap: `{analysis['target_present']}`",
        f"- Valid for Goodix protocol analysis: `{analysis['valid_for_protocol_analysis']}`",
        "",
        "## Conclusion",
        "",
        analysis["conclusion"],
        "",
        "## USB Device Descriptors Seen",
        "",
        "| Address | VID:PID | First frame | Frames |",
        "| --- | --- | ---: | ---: |",
    ]

    for item in analysis["descriptors"]:
        lines.append(
            "| {address} | `{vid}:{pid}` | {frame} | {frames} |".format(
                address=item["device_address"],
                vid=item["vendor_id"],
                pid=item["product_id"],
                frame=item["first_frame"],
                frames=item["descriptor_frames"],
            )
        )

    data_summary = analysis["data_summary"]
    lines.extend(
        [
            "",
            "## Data Summary",
            "",
            f"- Total payload-bearing USB rows: `{data_summary['data_frames']}`",
            f"- Target payload-bearing rows: `{data_summary['target_data_frames']}`",
            "",
            "| Address | Endpoint | Frames | Bytes |",
            "| --- | --- | ---: | ---: |",
        ]
    )

    for item in data_summary["by_address_endpoint"]:
        lines.append(
            "| {address} | `{endpoint}` | {frames} | {bytes_} |".format(
                address=item["device_address"],
                endpoint=item["endpoint_address"],
                frames=item["frames"],
                bytes_=item["bytes"],
            )
        )

    lines.extend(
        [
            "",
            "## Goodix Messages",
            "",
        ]
    )
    messages = analysis["goodix_messages"]
    if not messages["command_counts"]:
        lines.append("No target Goodix message-pack frames were decoded.")
    else:
        lines.extend(
            [
                "| Command | Name | Frames |",
                "| --- | --- | ---: |",
            ]
        )
        for item in messages["command_counts"]:
            lines.append(f"| `{item['command']}` | {item['name']} | {item['frames']} |")

    unattributed = analysis.get("unattributed_goodix_messages", {})
    if not analysis["target_present"] and unattributed.get("command_counts"):
        lines.extend(
            [
                "",
                "## Unattributed Goodix-Like Messages",
                "",
                "Goodix-like frames were found, but no descriptor captured the "
                "target address. Treat these as candidates only until the "
                "device identity is proven from the same pcap.",
                "",
                "| Address | Command | Name | Frames |",
                "| --- | --- | --- | ---: |",
            ]
        )
        for item in unattributed["command_counts"]:
            lines.append(
                "| {address} | `{command}` | {name} | {frames} |".format(
                    address=item.get("device_address", ""),
                    command=item["command"],
                    name=item["name"],
                    frames=item["frames"],
                )
            )

    lines.extend(
        [
            "",
            "## Next Capture Requirements",
            "",
            "- Start USBPcap on the host-controller interface whose device tree lists "
            "`VID_27C6&PID_521D`.",
            "- Save the USBPcap interface listing next to the pcap.",
            "- If the correct controller is uncertain, capture each USBPcap interface "
            "simultaneously and keep the files separate.",
            "- Re-run this analyzer before using the capture for `0xe4`, `0xe0`, "
            "`0xd0`, TLS, or `0x20` protocol work.",
            "",
        ]
    )
    return "\n".join(lines)


def parse_rows(result: TSharkResult) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in result.stdout.splitlines():
        values = line.split("\t")
        if len(values) < len(result.fields):
            values.extend([""] * (len(result.fields) - len(values)))
        rows.append(dict(zip(result.fields, values[: len(result.fields)], strict=True)))
    return rows


def summarize_descriptors(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    summary: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        vendor = _hex_int(row.get("usb.idVendor", ""))
        product = _hex_int(row.get("usb.idProduct", ""))
        address = row.get("usb.device_address", "")
        if vendor is None or product is None or not address:
            continue
        key = (address, f"{vendor:04x}", f"{product:04x}")
        item = summary.setdefault(
            key,
            {
                "device_address": address,
                "vendor_id": f"{vendor:04x}",
                "product_id": f"{product:04x}",
                "first_frame": _int(row.get("frame.number", "")) or 0,
                "first_time_relative": row.get("frame.time_relative", ""),
                "descriptor_frames": 0,
            },
        )
        item["descriptor_frames"] += 1
        frame = _int(row.get("frame.number", "")) or item["first_frame"]
        if frame < item["first_frame"]:
            item["first_frame"] = frame
            item["first_time_relative"] = row.get("frame.time_relative", "")

    return sorted(
        summary.values(),
        key=lambda item: (
            _int(item["device_address"]) or 0,
            item["vendor_id"],
            item["product_id"],
        ),
    )


def summarize_data(
    rows: list[dict[str, str]],
    target_addresses: set[str],
) -> dict[str, Any]:
    counts: Counter[tuple[str, str]] = Counter()
    byte_counts: Counter[tuple[str, str]] = Counter()
    target_frames = 0
    for row in rows:
        address = row.get("usb.device_address", "")
        endpoint = row.get("usb.endpoint_address", "") or "control"
        data_len = _int(row.get("usb.data_len", "")) or max(
            len(bytes.fromhex(blob.replace(":", ""))) for blob in _payload_blobs(row)
        )
        counts[(address, endpoint)] += 1
        byte_counts[(address, endpoint)] += data_len
        if address in target_addresses:
            target_frames += 1

    by_endpoint = [
        {
            "device_address": address,
            "endpoint_address": endpoint,
            "frames": frames,
            "bytes": byte_counts[(address, endpoint)],
        }
        for (address, endpoint), frames in counts.items()
    ]
    by_endpoint.sort(
        key=lambda item: (
            _int(item["device_address"]) or 0,
            item["endpoint_address"],
        )
    )

    return {
        "data_frames": len(rows),
        "target_data_frames": target_frames,
        "by_address_endpoint": by_endpoint,
    }


def decode_goodix_payloads(
    rows: list[dict[str, str]],
    target_addresses: set[str] | None,
) -> dict[str, Any]:
    counts: Counter[tuple[str, int]] = Counter()
    examples: list[dict[str, Any]] = []
    for row in rows:
        address = row.get("usb.device_address", "")
        if target_addresses is not None and address not in target_addresses:
            continue
        for blob in _payload_blobs(row):
            frame = _decode_goodix_message(bytes.fromhex(blob.replace(":", "")))
            if frame is None:
                continue
            command = frame["command"]
            counts[(address, command)] += 1
            if len(examples) < 16:
                examples.append(
                    {
                        "frame": _int(row.get("frame.number", "")),
                        "time_relative": row.get("frame.time_relative", ""),
                        "device_address": address,
                        "endpoint_address": row.get("usb.endpoint_address", ""),
                        "flag": f"0x{frame['flag']:02x}",
                        "command": f"0x{command:02x}",
                        "command_name": GOODIX_COMMANDS.get(command, "unknown"),
                        "payload_length": frame["payload_length"],
                    }
                )

    return {
        "command_counts": [
            {
                "device_address": address,
                "command": f"0x{command:02x}",
                "name": GOODIX_COMMANDS.get(command, "unknown"),
                "frames": frames,
            }
            for (address, command), frames in sorted(
                counts.items(),
                key=lambda item: (_int(item[0][0]) or 0, item[0][1]),
            )
        ],
        "examples": examples,
    }


def _decode_goodix_message(data: bytes) -> dict[str, int] | None:
    if len(data) < 8:
        return None
    flag = data[0]
    length = struct.unpack("<H", data[1:3])[0]
    if (sum(data[0:3]) & 0xFF) != data[3]:
        return None
    if len(data) < 4 + length:
        return None
    if flag == 0xB2:
        return {"flag": flag, "command": 0xB2, "payload_length": length}
    if flag not in (0xA0, 0xB0):
        return None
    payload = data[4 : 4 + length]
    if len(payload) < 4:
        return None
    command = payload[0]
    protocol_length = struct.unpack("<H", payload[1:3])[0]
    if protocol_length < 1 or len(payload) < protocol_length + 3:
        return None
    return {
        "flag": flag,
        "command": command,
        "payload_length": protocol_length - 1,
    }


def _payload_blobs(row: dict[str, str]) -> list[str]:
    blobs = []
    for field in ("usbhid.data", "usb.data_fragment", "usb.capdata"):
        value = row.get(field, "")
        if value:
            blobs.extend(part for part in value.split(",") if part)
    return blobs or ["00"]


def _run_tshark(
    pcap: Path,
    *,
    fields: tuple[str, ...],
    display_filter: str,
    tshark: str,
) -> TSharkResult:
    command = [
        tshark,
        "-r",
        str(pcap),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "separator=\t",
    ]
    for field in fields:
        command.extend(["-e", field])

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=120,
        )
    except FileNotFoundError as error:
        raise CaptureAnalysisError("tshark is not installed") from error
    except subprocess.TimeoutExpired as error:
        raise CaptureAnalysisError("tshark timed out") from error

    if completed.returncode != 0:
        raise CaptureAnalysisError(completed.stderr.strip() or "tshark failed")
    return TSharkResult(fields=fields, stdout=completed.stdout)


def _conclusion(
    target_addresses: set[str],
    data_summary: dict[str, Any],
    target_messages: dict[str, Any],
    unattributed_messages: dict[str, Any],
    vendor: int,
    product: int,
) -> str:
    target = f"{vendor:04x}:{product:04x}"
    if not target_addresses:
        if unattributed_messages["command_counts"]:
            return (
                f"The capture does not contain USB descriptors for `{target}`. "
                "It includes Goodix-like message frames at unattributed USB "
                "addresses, but those frames cannot be used as target protocol "
                "evidence until the same pcap proves the target address."
            )
        return (
            f"The capture does not contain USB descriptors for `{target}`. "
            "It cannot be used to infer Goodix production-data, TLS, or image "
            "commands. Any HID traffic in this pcap belongs to another captured "
            "USB device."
        )
    if data_summary["target_data_frames"] == 0:
        return (
            f"The target `{target}` enumerated, but no target payload-bearing USB "
            "rows were captured. Re-capture while starting Windows Hello flows."
        )
    if not target_messages["command_counts"]:
        return (
            f"The target `{target}` enumerated, but no Goodix message-pack or TLS "
            "data frames were decoded for that device address. The capture is "
            "descriptor/control-only for protocol purposes and cannot be used to "
            "infer `0xe4`, `0xd0`, TLS, or `0x20` behavior."
        )
    return (
        f"The capture contains target `{target}` traffic and can be inspected for "
        "Goodix command framing."
    )


def _hex_int(value: str) -> int | None:
    value_ = value.strip()
    if not value_:
        return None
    try:
        return int(value_, 0)
    except ValueError:
        return None


def _int(value: str) -> int | None:
    value_ = value.strip()
    if not value_:
        return None
    try:
        return int(value_, 10)
    except ValueError:
        return None
