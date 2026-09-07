"""Synthetic-only tests for the driver's file-based PSK self-check.

The check is sha256(PSK file) == device 0xbb020001 readback, fail-closed via
plain asserts. No hardware, no secrets on disk beyond the tmp files here.
"""

from __future__ import annotations

import hashlib

import pytest

import driver_52xd


def make_device(hash_reply: bytes):
    class Device:
        def firmware_version(self):
            return "GFUSB_GM168SEC_APP_10034"

        def preset_psk_read(self, selector, length, off):
            assert selector == 0xbb020001 and length == 32
            return (True, selector, hash_reply)

    return Device()


def write_psk(tmp_path, psk: bytes):
    p = tmp_path / "psk.bin"
    p.write_bytes(psk)
    return str(p)


def test_happy_path_returns_psk(tmp_path):
    psk = bytes(range(32))
    device = make_device(hashlib.sha256(psk).digest())
    assert driver_52xd._verify_and_get_psk(device, write_psk(tmp_path, psk)) == psk


def test_mismatched_hash_fails_closed(tmp_path):
    psk = bytes(range(32))
    device = make_device(hash_reply=bytes(32))
    with pytest.raises(AssertionError):
        driver_52xd._verify_and_get_psk(device, write_psk(tmp_path, psk))


def test_wrong_length_fails_closed(tmp_path):
    psk = bytes(range(16))
    device = make_device(hashlib.sha256(psk).digest())
    with pytest.raises(AssertionError):
        driver_52xd._verify_and_get_psk(device, write_psk(tmp_path, psk))


def test_missing_psk_file_fails_closed():
    device = make_device(bytes(32))
    with pytest.raises(AssertionError):
        driver_52xd._verify_and_get_psk(device, "")
