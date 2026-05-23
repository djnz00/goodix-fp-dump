from __future__ import annotations

import subprocess

import pytest

from goodix_fp_dump import device_info

pytestmark = pytest.mark.unit


def test_run_command_reports_missing_command() -> None:
    result = device_info.run_command(["definitely-not-a-goodix-tool"])

    assert result["missing"] is True
    assert result["command"] == ["definitely-not-a-goodix-tool"]


def test_run_command_reports_timeout(monkeypatch) -> None:
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(["tool"], timeout=0.1)

    monkeypatch.setattr(device_info.subprocess, "run", fake_run)

    assert device_info.run_command(["tool"], timeout=0.1)["timeout"] == 0.1


def test_usb_device_info_when_missing(monkeypatch) -> None:
    monkeypatch.setattr(device_info.usb.core, "find", lambda **kwargs: None)

    assert device_info.usb_device_info(0x27C6, 0x521D) == {
        "vendor_id": "27c6",
        "product_id": "521d",
        "found": False,
    }


def test_package_versions_marks_missing_package() -> None:
    result = device_info.package_versions(["definitely-missing-package"])

    assert result == {"definitely-missing-package": None}
