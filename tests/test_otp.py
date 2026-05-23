from __future__ import annotations

import pytest

from goodix_fp_dump.firmware import OTPStatus, classify_otp, classify_otp_error

pytestmark = pytest.mark.unit


def test_classify_empty_otp() -> None:
    assert classify_otp(b"").status == OTPStatus.EMPTY


def test_classify_short_otp() -> None:
    result = classify_otp(b"\x01\x02")

    assert result.status == OTPStatus.SHORT
    assert result.length == 2
    assert result.data_hex == "0102"


def test_classify_all_zero_otp_as_malformed() -> None:
    result = classify_otp(bytes(64))

    assert result.status == OTPStatus.MALFORMED
    assert result.error == "all-zero OTP payload"


def test_classify_valid_otp() -> None:
    result = classify_otp(bytes(range(64)))

    assert result.ok
    assert result.status == OTPStatus.VALID
    assert result.length == 64


def test_classify_timeout_error_as_transient() -> None:
    result = classify_otp_error(TimeoutError("read timeout"))

    assert result.status == OTPStatus.TRANSIENT_FAILURE
    assert result.error == "read timeout"


def test_classify_state_error() -> None:
    assert (
        classify_otp_error(RuntimeError("invalid device state")).status
        == OTPStatus.INVALID_STATE
    )
