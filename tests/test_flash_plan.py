from __future__ import annotations

import pytest

from goodix_fp_dump.firmware import build_flash_plan
from goodix_fp_dump.safety import DestructiveOperationError

pytestmark = pytest.mark.unit


def test_flash_plan_requires_stock_dump_hash() -> None:
    with pytest.raises(DestructiveOperationError, match="stock dump"):
        build_flash_plan(
            product=0x521D,
            firmware_family="52xd",
            target="27c6:521d",
            stock_dump_sha256="",
            confirmation="27c6:521d",
            psk_evidence=True,
        )


def test_flash_plan_requires_matching_confirmation() -> None:
    with pytest.raises(DestructiveOperationError, match="confirmation"):
        build_flash_plan(
            product=0x521D,
            firmware_family="52xd",
            target="27c6:521d",
            stock_dump_sha256="b" * 64,
            confirmation="wrong",
            psk_evidence=True,
        )


def test_flash_plan_requires_psk_evidence() -> None:
    with pytest.raises(DestructiveOperationError, match="PSK"):
        build_flash_plan(
            product=0x521D,
            firmware_family="52xd",
            target="27c6:521d",
            stock_dump_sha256="b" * 64,
            confirmation="27c6:521d",
            psk_evidence=False,
        )
