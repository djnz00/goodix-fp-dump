from __future__ import annotations

import subprocess
import time
from typing import Any


def reset_usb_device(
    vendor: int,
    product: int,
    *,
    settle_seconds: float = 1.0,
) -> dict[str, Any]:
    target = f"{vendor:04x}:{product:04x}"
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
