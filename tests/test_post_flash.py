from __future__ import annotations

import os
import subprocess

import pytest

pytestmark = [pytest.mark.hardware, pytest.mark.flash]


def test_post_flash_liveness_lsusb() -> None:
    if os.environ.get("GOODIX_HW") != "1" or os.environ.get("GOODIX_FLASH") != "1":
        pytest.skip("set GOODIX_HW=1 and GOODIX_FLASH=1 to enable post-flash tests")

    result = subprocess.run(
        ["lsusb", "-d", os.environ.get("GOODIX_TARGET", "27c6:521d")],
        capture_output=True,
        check=False,
        text=True,
        timeout=5,
    )

    assert result.returncode == 0
    assert os.environ.get("GOODIX_TARGET", "27c6:521d") in result.stdout.lower()
