from __future__ import annotations

import os

import pytest

from goodix_fp_dump.firmware import build_flash_plan

pytestmark = [pytest.mark.hardware, pytest.mark.flash]


def _flash_env():
    if os.environ.get("GOODIX_HW") != "1" or os.environ.get("GOODIX_FLASH") != "1":
        pytest.skip("set GOODIX_HW=1 and GOODIX_FLASH=1 to enable flash tests")
    return {
        "target": os.environ["GOODIX_TARGET"],
        "product": int(os.environ.get("GOODIX_PRODUCT", "0x521d"), 0),
        "family": os.environ.get("GOODIX_FIRMWARE_FAMILY", "52xd"),
        "stock_sha256": os.environ["GOODIX_STOCK_SHA256"],
        "confirm": os.environ["GOODIX_CONFIRM"],
    }


def test_flash_plan_preconditions_are_complete() -> None:
    env = _flash_env()

    plan = build_flash_plan(
        product=env["product"],
        firmware_family=env["family"],
        target=env["target"],
        stock_dump_sha256=env["stock_sha256"],
        confirmation=env["confirm"],
        psk_evidence=True,
    )

    assert plan["product"] == f"{env['product']:04x}"


def test_flash_execution_is_not_implemented_without_device_runner() -> None:
    _flash_env()
    pytest.skip("flash execution needs the finalized hardware runner command")
