from __future__ import annotations

import json
import struct

import pytest

import goodix
from goodix_fp_dump import production
from goodix_fp_dump.archive import ArchiveRun
from goodix_fp_dump.production import ProductionSelector

pytestmark = pytest.mark.unit


def test_read_production_data_archives_selector_payloads(tmp_path, monkeypatch) -> None:
    class FakeDevice:
        def __init__(self, product, proto, timeout):
            pass

        def nop(self):
            return None

        def firmware_version(self):
            return "GFUSB_GM168SEC_APP_TEST"

        def preset_psk_read(self, flags, length, number):
            return True, flags, bytes([flags & 0xFF]) * min(length, 4)

        def disconnect(self):
            return None

    monkeypatch.setattr(goodix, "Device", FakeDevice)
    monkeypatch.setattr(
        production,
        "collect_preflight",
        lambda *args, **kwargs: {"command_path": kwargs["command_path"]},
    )

    archive = ArchiveRun.create(tmp_path, 0x27C6, 0x521D)
    manifest = production.read_production_data(
        archive=archive,
        vendor=0x27C6,
        product=0x521D,
        selectors=(ProductionSelector("sample", 0xBB020001, length=8),),
        reset_usb=False,
    )

    assert manifest["status"] == "ok"
    item = manifest["production_data"][0]
    assert item["returned_flags"] == "0xbb020001"
    assert item["returned_length"] == 4
    assert (archive.path / item["artifact"]["path"]).read_bytes() == b"\x01" * 4


def test_read_production_data_records_selector_failure_without_raw_artifact(
    tmp_path,
    monkeypatch,
) -> None:
    class FakeDevice:
        def __init__(self, product, proto, timeout):
            pass

        def nop(self):
            return None

        def firmware_version(self):
            return "GFUSB_GM168SEC_APP_TEST"

        def preset_psk_read(self, flags, length, number):
            return False, None, None

        def disconnect(self):
            return None

    monkeypatch.setattr(goodix, "Device", FakeDevice)
    monkeypatch.setattr(
        production,
        "collect_preflight",
        lambda *args, **kwargs: {"command_path": kwargs["command_path"]},
    )

    archive = ArchiveRun.create(tmp_path, 0x27C6, 0x521D)
    manifest = production.read_production_data(
        archive=archive,
        vendor=0x27C6,
        product=0x521D,
        selectors=(ProductionSelector("missing", 0xBB010002, length=114),),
        reset_usb=False,
    )

    assert manifest["status"] == "partial"
    assert manifest["production_data"][0] == {
        "name": "missing",
        "flags": "0xbb010002",
        "length": 114,
        "number": 0,
        "firmware_version": "GFUSB_GM168SEC_APP_TEST",
        "ok": False,
    }


def test_probe_production_read_variants_archives_tlv_response(
    tmp_path,
    monkeypatch,
) -> None:
    response = (
        b"\x00"
        + struct.pack("<II", 0xBB020001, 4)
        + b"abcd"
    )
    transport = None

    class FakeTransport:
        def __init__(self):
            self.writes = []
            self.reads = [
                goodix.encode_message_pack(
                    goodix.encode_message_protocol(
                        response,
                        goodix.COMMAND_PRESET_PSK_READ_R,
                    )
                )
            ]

        def write(self, data):
            self.writes.append(data)

        def read(self):
            return self.reads.pop(0)

    class FakeDevice:
        def __init__(self, product, proto, timeout):
            nonlocal transport
            transport = FakeTransport()
            self.protocol = transport

        def nop(self):
            return None

        def firmware_version(self):
            return "GFUSB_GM168SEC_APP_TEST"

        def disconnect(self):
            return None

    monkeypatch.setattr(goodix, "Device", FakeDevice)
    monkeypatch.setattr(
        production,
        "collect_preflight",
        lambda *args, **kwargs: {"command_path": kwargs["command_path"]},
    )

    archive = ArchiveRun.create(tmp_path, 0x27C6, 0x521D)
    manifest = production.probe_production_read_variants(
        archive=archive,
        vendor=0x27C6,
        product=0x521D,
        selectors=(ProductionSelector("hash", 0xBB020001, length=4),),
        variants=(production.PRODUCTION_READ_VARIANTS[1],),
        reset_usb=False,
    )

    assert manifest["status"] == "ok"
    item = manifest["variant_results"][0]
    assert item["ok"] is True
    assert item["returned_type"] == "0xbb020001"
    assert item["returned_payload_length"] == 4
    assert item["available_payload_length"] == 4
    assert "abcd" not in json.dumps(manifest)
    assert (
        archive.path / item["response"]["artifact"]["path"]
    ).read_bytes() == response

    assert transport is not None
    sent_payload = goodix.check_message_protocol(
        goodix.check_message_pack(transport.writes[0]),
        goodix.COMMAND_PRESET_PSK_READ_R,
    )
    assert sent_payload == struct.pack("<II", 0xBB020001, 0)


def test_probe_production_read_variants_records_mcu_failure(
    tmp_path,
    monkeypatch,
) -> None:
    response = b"\x04\x01"

    class FakeTransport:
        def write(self, data):
            pass

        def read(self):
            return goodix.encode_message_pack(
                goodix.encode_message_protocol(
                    response,
                    goodix.COMMAND_PRESET_PSK_READ_R,
                )
            )

    class FakeDevice:
        def __init__(self, product, proto, timeout):
            self.protocol = FakeTransport()

        def nop(self):
            return None

        def firmware_version(self):
            return "GFUSB_GM168SEC_APP_TEST"

        def disconnect(self):
            return None

    monkeypatch.setattr(goodix, "Device", FakeDevice)
    monkeypatch.setattr(
        production,
        "collect_preflight",
        lambda *args, **kwargs: {"command_path": kwargs["command_path"]},
    )

    archive = ArchiveRun.create(tmp_path, 0x27C6, 0x521D)
    manifest = production.probe_production_read_variants(
        archive=archive,
        vendor=0x27C6,
        product=0x521D,
        selectors=(ProductionSelector("hash", 0xBB020001, length=4),),
        variants=(production.PRODUCTION_READ_VARIANTS[1],),
        reset_usb=False,
    )

    assert manifest["status"] == "partial"
    item = manifest["variant_results"][0]
    assert item["ok"] is False
    assert item["mcu_status"] == "0x04"
    assert item["mcu_status_detail"] == "0x01"
    assert (
        archive.path / item["response"]["artifact"]["path"]
    ).read_bytes() == response
