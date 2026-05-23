from __future__ import annotations

import pytest

from goodix_fp_dump.safety import (
    DestructiveOperationError,
    SafetyPlan,
    assert_read_only,
)

pytestmark = pytest.mark.unit


def test_read_only_allows_non_destructive_operation() -> None:
    assert_read_only("read_otp")


def test_read_only_rejects_destructive_operation() -> None:
    with pytest.raises(DestructiveOperationError, match="erase_firmware"):
        assert_read_only("erase_firmware")


def test_safety_plan_allows_read_only_operations() -> None:
    SafetyPlan(target="27c6:521d", operations=("read_otp",)).validate()


def test_safety_plan_requires_confirmation_for_flash() -> None:
    with pytest.raises(DestructiveOperationError, match="allow_write"):
        SafetyPlan(target="27c6:521d", operations=("flash_firmware",)).validate()


def test_safety_plan_accepts_complete_destructive_context() -> None:
    SafetyPlan(
        target="27c6:521d",
        allow_write=True,
        confirmation="27c6:521d",
        stock_dump_sha256="a" * 64,
        firmware_family="52xd",
        psk_evidence=True,
        operations=("flash_firmware",),
    ).validate()
