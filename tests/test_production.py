from __future__ import annotations

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
