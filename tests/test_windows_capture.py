from __future__ import annotations

import json

import pytest

from goodix_fp_dump import windows_capture
from goodix_fp_dump.windows_capture import TSharkResult

pytestmark = pytest.mark.unit


def test_summarize_descriptors_identifies_target_addresses() -> None:
    rows = windows_capture.parse_rows(
        TSharkResult(
            fields=windows_capture.DESCRIPTOR_FIELDS,
            stdout=(
                "20\t0.0\t3\t0x0b05\t0x19b6\t0x01\n100\t1.0\t7\t0x27c6\t0x521d\t0x01\n"
            ),
        )
    )

    descriptors = windows_capture.summarize_descriptors(rows)

    assert descriptors == [
        {
            "device_address": "3",
            "vendor_id": "0b05",
            "product_id": "19b6",
            "first_frame": 20,
            "first_time_relative": "0.0",
            "descriptor_frames": 1,
        },
        {
            "device_address": "7",
            "vendor_id": "27c6",
            "product_id": "521d",
            "first_frame": 100,
            "first_time_relative": "1.0",
            "descriptor_frames": 1,
        },
    ]


def test_analyze_capture_reports_wrong_usbpcap_controller(
    monkeypatch, tmp_path
) -> None:
    calls: list[str] = []

    def fake_run_tshark(pcap, *, fields, display_filter, tshark):
        calls.append(display_filter)
        if fields == windows_capture.DESCRIPTOR_FIELDS:
            return TSharkResult(
                fields=fields,
                stdout="20\t0.0\t3\t0x0b05\t0x19b6\t0x01\n",
            )
        return TSharkResult(
            fields=fields,
            stdout=(
                "49557\t514.0\t3\t1.3.1\thost\t0x81\t32\t0x01\t"
                "5d01000000000000000000000000000000000000000000000000000000000000"
                "\t\t\n"
            ),
        )

    monkeypatch.setattr(windows_capture, "_run_tshark", fake_run_tshark)

    analysis = windows_capture.analyze_capture(tmp_path / "capture.pcap")

    assert analysis["target_present"] is False
    assert analysis["valid_for_protocol_analysis"] is False
    assert analysis["target_addresses"] == []
    assert "does not contain USB descriptors" in analysis["conclusion"]
    assert analysis["data_summary"]["target_data_frames"] == 0
    assert calls


def test_goodix_message_decode_counts_target_commands(monkeypatch, tmp_path) -> None:
    message = _goodix_pack(0xE4, b"\x01\x00")

    def fake_run_tshark(pcap, *, fields, display_filter, tshark):
        if fields == windows_capture.DESCRIPTOR_FIELDS:
            return TSharkResult(
                fields=fields,
                stdout="100\t1.0\t7\t0x27c6\t0x521d\t0x01\n",
            )
        return TSharkResult(
            fields=fields,
            stdout=(
                "101\t1.1\t7\thost\t1.7.1\t0x01\t"
                f"{len(message)}\t0x03\t\t\t{message.hex()}\n"
            ),
        )

    monkeypatch.setattr(windows_capture, "_run_tshark", fake_run_tshark)

    analysis = windows_capture.analyze_capture(tmp_path / "capture.pcap")

    assert analysis["valid_for_protocol_analysis"] is True
    assert analysis["goodix_messages"]["command_counts"] == [
        {
            "device_address": "7",
            "command": "0xe4",
            "name": "preset-psk-read",
            "frames": 1,
        }
    ]


def test_descriptor_only_target_capture_is_not_protocol_valid(
    monkeypatch,
    tmp_path,
) -> None:
    def fake_run_tshark(pcap, *, fields, display_filter, tshark):
        if fields == windows_capture.DESCRIPTOR_FIELDS:
            return TSharkResult(
                fields=fields,
                stdout="2\t0.0\t1\t0x27c6\t0x521d\t0x01\n",
            )
        return TSharkResult(
            fields=fields,
            stdout=(
                "2\t0.0\t1\thost\t1.1.0\t0x80\t18\t0x02\t\t\t"
                "1201000200000040c6271d52000001020301\n"
            ),
        )

    monkeypatch.setattr(windows_capture, "_run_tshark", fake_run_tshark)

    analysis = windows_capture.analyze_capture(tmp_path / "capture.pcap")

    assert analysis["target_present"] is True
    assert analysis["data_summary"]["target_data_frames"] == 1
    assert analysis["valid_for_protocol_analysis"] is False
    assert analysis["goodix_messages"]["command_counts"] == []
    assert "descriptor/control-only" in analysis["conclusion"]


def test_analyze_capture_reports_unattributed_goodix_candidates(
    monkeypatch,
    tmp_path,
) -> None:
    message = _goodix_pack(0xD0, b"\x01")

    def fake_run_tshark(pcap, *, fields, display_filter, tshark):
        if fields == windows_capture.DESCRIPTOR_FIELDS:
            return TSharkResult(fields=fields, stdout="")
        return TSharkResult(
            fields=fields,
            stdout=(
                "42\t2.0\t9\thost\t1.9.1\t0x01\t"
                f"{len(message)}\t0x03\t\t\t{message.hex()}\n"
            ),
        )

    monkeypatch.setattr(windows_capture, "_run_tshark", fake_run_tshark)

    analysis = windows_capture.analyze_capture(tmp_path / "capture.pcap")

    assert analysis["target_present"] is False
    assert analysis["valid_for_protocol_analysis"] is False
    assert analysis["goodix_messages"]["command_counts"] == []
    assert analysis["unattributed_goodix_messages"]["command_counts"] == [
        {
            "device_address": "9",
            "command": "0xd0",
            "name": "request-tls-connection",
            "frames": 1,
        }
    ]
    assert "Goodix-like message frames" in analysis["conclusion"]


def test_write_analysis_report_outputs_json_and_markdown(tmp_path) -> None:
    analysis = {
        "pcap": "capture.pcap",
        "target": {"vendor_id": "27c6", "product_id": "521d"},
        "target_present": False,
        "valid_for_protocol_analysis": False,
        "descriptors": [],
        "data_summary": {
            "data_frames": 0,
            "target_data_frames": 0,
            "by_address_endpoint": [],
        },
        "goodix_messages": {"command_counts": [], "examples": []},
        "unattributed_goodix_messages": {"command_counts": [], "examples": []},
        "conclusion": "No target traffic.",
    }

    windows_capture.write_analysis_report(
        analysis,
        json_path=tmp_path / "analysis.json",
        markdown_path=tmp_path / "analysis.md",
    )

    assert json.loads((tmp_path / "analysis.json").read_text()) == analysis
    assert "# Windows USB Capture Analysis" in (tmp_path / "analysis.md").read_text()


def _goodix_pack(command: int, payload: bytes) -> bytes:
    protocol = bytes([command]) + (len(payload) + 1).to_bytes(2, "little") + payload
    protocol += bytes([(0xAA - sum(protocol)) & 0xFF])
    header = b"\xa0" + len(protocol).to_bytes(2, "little")
    return header + bytes([sum(header) & 0xFF]) + protocol
