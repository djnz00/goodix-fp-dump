from __future__ import annotations

import pytest

from goodix_fp_dump.firmware import (
    FirmwareCompatibilityError,
    build_flash_plan,
    family_for_product,
    validate_product_family,
)

pytestmark = pytest.mark.unit


def test_family_for_521d() -> None:
    assert family_for_product(0x521D).name == "52xd"


def test_unknown_product_is_rejected() -> None:
    with pytest.raises(FirmwareCompatibilityError, match="unknown"):
        family_for_product(0x5125)


def test_cross_family_product_is_rejected() -> None:
    with pytest.raises(FirmwareCompatibilityError, match="not compatible"):
        validate_product_family(0x521D, "53x5")


def test_build_flash_plan_records_compatible_family() -> None:
    plan = build_flash_plan(
        product=0x521D,
        firmware_family="52xd",
        target="27c6:521d",
        stock_dump_sha256="b" * 64,
        confirmation="27c6:521d",
        psk_evidence=True,
    )

    assert plan["product"] == "521d"
    assert plan["firmware_family"] == "52xd"
    assert plan["operations"] == ["flash_firmware"]
