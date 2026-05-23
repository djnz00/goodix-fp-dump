from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.manual


def test_fingerprint_enrollment_acceptance_requires_operator() -> None:
    if os.environ.get("GOODIX_MANUAL") != "1":
        pytest.skip("set GOODIX_MANUAL=1 to run enrollment acceptance")
    pytest.skip("wire this to the finalized libfprint enrollment command")


def test_fingerprint_verification_acceptance_requires_operator() -> None:
    if os.environ.get("GOODIX_MANUAL") != "1":
        pytest.skip("set GOODIX_MANUAL=1 to run verification acceptance")
    pytest.skip("wire this to the finalized libfprint verification command")
