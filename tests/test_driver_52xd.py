import pytest

import driver_52xd

from driver_52xd import classify_device_psk_state

pytestmark = pytest.mark.unit


def test_unknown_hash_is_not_unprovisioned():
    assert classify_device_psk_state((True, 0xbb020001, bytes(32))) == (
        "unknown_device_hash"
    )


@pytest.mark.parametrize(
    "reply",
    [
        None,
        (),
        (True, 0xbb020001),
        (False, 0xbb020001, bytes(32)),
        (True, 0, bytes(32)),
        (True, 0xbb020001, None),
    ],
)
def test_invalid_or_unreadable_reply(reply):
    assert classify_device_psk_state(reply) == "invalid/unreadable"


def test_otp_diagnostics_calls_device_otp_operation(monkeypatch):
    otp = bytes(range(64))
    calls = []

    def read_otp(device):
        calls.append(device)
        return otp

    monkeypatch.setattr(driver_52xd.goodix.Device, "read_otp", read_otp)
    device = object()

    result = driver_52xd.read_otp_diagnostics(device, retries=0)

    assert result.ok
    assert result.length == len(otp)
    assert calls == [device]
