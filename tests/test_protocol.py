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


class FakeUSBDevice:
    def __init__(self, *transfers: bytes) -> None:
        self.transfers = iter(transfers)
        self.reads: list[tuple[int, int, int]] = []
        self.calls: list[str] = []

    def read(self, endpoint: int, size: int, timeout: int) -> memoryview:
        self.reads.append((endpoint, size, timeout))
        return memoryview(next(self.transfers))


def usb_protocol_for(monkeypatch: pytest.MonkeyPatch,
                     device: FakeUSBDevice) -> protocol.USBProtocol:
    interface = type("Interface", (), {
        "bInterfaceClass": protocol.usb.legacy.CLASS_DATA,
        "bInterfaceNumber": 1,
    })()
    endpoint_in = type("Endpoint", (), {
        "bEndpointAddress": 0x81,
        "bmAttributes": protocol.usb.legacy.ENDPOINT_TYPE_BULK,
    })()
    endpoint_out = type("Endpoint", (), {
        "bEndpointAddress": 0x02,
        "bmAttributes": protocol.usb.legacy.ENDPOINT_TYPE_BULK,
    })()
    configuration = object()
    monkeypatch.setattr(protocol.usb.core, "find", lambda **kwargs: device)
    monkeypatch.setattr(protocol.usb.control, "get_status", lambda device: None)
    monkeypatch.setattr(protocol.usb.util, "find_descriptor",
                        lambda parent, custom_match: (
                            interface if parent is configuration
                            else endpoint_in if custom_match(endpoint_in)
                            else endpoint_out
                        ))
    monkeypatch.setattr(protocol.usb.util, "claim_interface", lambda *args: None)
    monkeypatch.setattr(protocol.USBProtocol, "_clear_endpoint_halts", lambda self: None)
    monkeypatch.setattr(device, "get_active_configuration", lambda: configuration,
                        raising=False)
    monkeypatch.setattr(device, "is_kernel_driver_active", lambda interface: False,
                        raising=False)
    monkeypatch.setattr(device, "set_configuration", lambda: None,
                        raising=False)
    device.product = device.manufacturer = "test"
    device.bus = device.address = 0
    return protocol.USBProtocol(0x27C6, 0x521D)


def test_usb_read_returns_one_message_pack_and_keeps_trailing_pack(
        monkeypatch: pytest.MonkeyPatch) -> None:
    first = b"\xa0\x01\x00\xa1a"
    second = b"\xa0\x02\x00\xa2bc"
    device = FakeUSBDevice(first + second)
    usb_protocol = usb_protocol_for(monkeypatch, device)

    assert usb_protocol.read() == first
    assert usb_protocol.read() == second
    assert len(device.reads) == 1


def test_strict_read_only_skips_usb_state_mutations(
        monkeypatch: pytest.MonkeyPatch) -> None:
    device = FakeUSBDevice(b"\xa0\x01\x00\xa1a")
    interface = type("Interface", (), {
        "bInterfaceClass": protocol.usb.legacy.CLASS_DATA,
        "bInterfaceNumber": 1,
    })()
    endpoint_in = type("Endpoint", (), {
        "bEndpointAddress": 0x81,
        "bmAttributes": protocol.usb.legacy.ENDPOINT_TYPE_BULK,
    })()
    endpoint_out = type("Endpoint", (), {
        "bEndpointAddress": 0x02,
        "bmAttributes": protocol.usb.legacy.ENDPOINT_TYPE_BULK,
    })()
    configuration = object()
    monkeypatch.setattr(protocol.usb.core, "find", lambda **kwargs: device)
    monkeypatch.setattr(protocol.usb.control, "get_status", lambda device: None)
    monkeypatch.setattr(protocol.usb.util, "find_descriptor",
                        lambda parent, custom_match: (
                            interface if parent is configuration
                            else endpoint_in if custom_match(endpoint_in)
                            else endpoint_out))
    monkeypatch.setattr(device, "get_active_configuration", lambda: configuration,
                        raising=False)
    monkeypatch.setattr(device, "is_kernel_driver_active", lambda interface: True,
                        raising=False)
    for name in ("detach_kernel_driver", "set_configuration", "clear_halt",
                 "attach_kernel_driver"):
        monkeypatch.setattr(device, name,
                            lambda *args, _name=name: device.calls.append(_name),
                            raising=False)
    monkeypatch.setattr(protocol.usb.util, "claim_interface",
                        lambda *args: device.calls.append("claim"))
    monkeypatch.setattr(protocol.usb.util, "release_interface",
                        lambda *args: device.calls.append("release"))
    monkeypatch.setattr(protocol.usb.util, "dispose_resources",
                        lambda *args: device.calls.append("dispose"))
    device.product = device.manufacturer = "test"
    device.bus = device.address = 0

    transport = protocol.USBProtocol(0x27C6, 0x521D, strict_read_only=True)
    assert transport.read() == b"\xa0\x01\x00\xa1a"
    transport.disconnect()
    assert device.calls == ["dispose"]


def test_usb_read_buffers_truncated_transfer_until_pack_is_complete(
        monkeypatch: pytest.MonkeyPatch) -> None:
    device = FakeUSBDevice(b"\xa0\x03\x00\xa3ab", b"c")
    usb_protocol = usb_protocol_for(monkeypatch, device)

    assert usb_protocol.read() == b"\xa0\x03\x00\xa3abc"
    assert len(device.reads) == 2


def test_usb_read_rejects_oversized_frame(monkeypatch: pytest.MonkeyPatch) -> None:
    length = protocol.USBProtocol.MAX_FRAME_LENGTH
    header = bytes((0xa0, length & 0xff, length >> 8))
    device = FakeUSBDevice(header + bytes((sum(header) & 0xff,)))
    usb_protocol = usb_protocol_for(monkeypatch, device)

    with pytest.raises(ValueError, match="too large"):
        usb_protocol.read()


def test_usb_read_rejects_malformed_header(monkeypatch: pytest.MonkeyPatch) -> None:
    device = FakeUSBDevice(b"\xa0\x01\x00\x00a")
    usb_protocol = usb_protocol_for(monkeypatch, device)

    with pytest.raises(ValueError, match="Invalid USB message pack header"):
        usb_protocol.read()


def test_usb_read_rejects_truncated_transfer(monkeypatch: pytest.MonkeyPatch) -> None:
    device = FakeUSBDevice(b"\xa0\x03\x00\xa3ab", b"")
    usb_protocol = usb_protocol_for(monkeypatch, device)

    with pytest.raises(ValueError, match="Truncated"):
        usb_protocol.read()
