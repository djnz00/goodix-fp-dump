from __future__ import annotations

import pytest

import protocol

pytestmark = pytest.mark.unit


class FakeProtocol(protocol.Protocol):
    def __init__(self, vendor: int, product: int, timeout: float | None = 5):
        self.vendor = vendor
        self.product = product
        self.timeout = timeout
        self.writes: list[bytes] = []

    def write(self, data: bytes, timeout: float | None = 5):
        self.writes.append(data)

    def read(self, size: int = 0x4000, timeout: float | None = 5) -> bytes:
        return b""

    def disconnect(self, timeout: float | None = 5):
        self.timeout = timeout


def test_protocol_subclass_records_constructor_values() -> None:
    fake = FakeProtocol(0x27C6, 0x521D, timeout=0.25)

    assert fake.vendor == 0x27C6
    assert fake.product == 0x521D
    assert fake.timeout == 0.25


def test_protocol_subclass_records_writes() -> None:
    fake = FakeProtocol(0x27C6, 0x521D)

    fake.write(b"abc")

    assert fake.writes == [b"abc"]
