from __future__ import annotations

import subprocess

import pytest

from goodix_fp_dump import usb_reset

pytestmark = pytest.mark.unit


def test_reset_usb_device_falls_back_to_sudo(monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run(command, capture_output, text, check):
        calls.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="ok" if command[0] == "sudo" else "",
            stderr="can't open [Permission denied]" if command[0] != "sudo" else "",
        )

    monkeypatch.setattr(usb_reset.sys, "platform", "linux")
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(usb_reset.time, "sleep", lambda seconds: None)

    result = usb_reset.reset_usb_device(0x27C6, 0x521D)

    assert result["ok"]
    assert calls == [["usbreset", "27c6:521d"], ["sudo", "-n", "usbreset", "27c6:521d"]]


def test_reset_usb_device_uses_pnp_device_on_windows(monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run(command, capture_output, text, check):
        calls.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=r"USB\VID_27C6&PID_521D\6&13C452C7&0&3",
            stderr="",
        )

    monkeypatch.setattr(usb_reset.sys, "platform", "win32")
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(usb_reset.time, "sleep", lambda seconds: None)

    result = usb_reset.reset_usb_device(0x27C6, 0x521D)

    assert result["ok"]
    assert result["target"] == "27c6:521d"
    assert calls[0][:4] == [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
    ]
    assert "USB\\VID_27C6&PID_521D*" in calls[0][-1]
    assert "Disable-PnpDevice" in calls[0][-1]
    assert "Enable-PnpDevice" in calls[0][-1]
