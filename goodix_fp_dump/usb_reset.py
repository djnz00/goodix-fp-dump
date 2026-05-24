from __future__ import annotations

import subprocess
import sys
import time
from typing import Any


def reset_usb_device(
    vendor: int,
    product: int,
    *,
    settle_seconds: float = 1.0,
) -> dict[str, Any]:
    target = f"{vendor:04x}:{product:04x}"
    if sys.platform == "win32":
        return _reset_windows_usb_device(vendor, product, settle_seconds=settle_seconds)

    attempts: list[dict[str, Any]] = []
    for command in (["usbreset", target], ["sudo", "-n", "usbreset", target]):
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        attempts.append(
            {
                "command": command,
                "returncode": result.returncode,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
            }
        )
        output = f"{result.stdout}\n{result.stderr}".lower()
        failed_output = "permission denied" in output or "can't open" in output
        if result.returncode == 0 and not failed_output:
            time.sleep(settle_seconds)
            return {"target": target, "ok": True, "attempts": attempts}
    return {"target": target, "ok": False, "attempts": attempts}


def _reset_windows_usb_device(
    vendor: int,
    product: int,
    *,
    settle_seconds: float,
) -> dict[str, Any]:
    target = f"{vendor:04x}:{product:04x}"
    instance_pattern = f"USB\\VID_{vendor:04X}&PID_{product:04X}*"
    command = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        (
            "$ErrorActionPreference = 'Stop'; "
            f"$pattern = '{instance_pattern}'; "
            "$device = Get-PnpDevice -PresentOnly | "
            "Where-Object { $_.InstanceId -like $pattern } | "
            "Select-Object -First 1; "
            "if ($null -eq $device) { "
            "Write-Error \"device not found: $pattern\"; exit 2 "
            "} "
            "Disable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false; "
            "Start-Sleep -Milliseconds 500; "
            "Enable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false; "
            "Write-Output $device.InstanceId"
        ),
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    attempt = {
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }
    if result.returncode == 0:
        time.sleep(settle_seconds)
        return {"target": target, "ok": True, "attempts": [attempt]}

    return {"target": target, "ok": False, "attempts": [attempt]}
