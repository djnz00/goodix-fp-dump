from __future__ import annotations

import json

import pytest

import goodix
from goodix_fp_dump.archive import ArchiveRun
from goodix_fp_dump import tls_probe

pytestmark = pytest.mark.unit


def test_probe_device_tls_archives_inprocess_transcript(tmp_path, monkeypatch) -> None:
    writes: list[bytes] = []

    class FakeProtocol:
        def read(self, timeout):
            return goodix.encode_message_pack(
                b"client-finished",
                goodix.FLAGS_TRANSPORT_LAYER_SECURITY,
            )

        def write(self, data):
            writes.append(data)

    class FakeDevice:
        def __init__(self, product, proto, timeout):
            self.protocol = FakeProtocol()

        def nop(self):
            return None

        def firmware_version(self):
            return "GFUSB_GM168SEC_APP_TEST"

        def request_tls_connection(self):
            return b"client-hello"

        def disconnect(self):
            return None

    class FakeTLS:
        def __init__(self, psk):
            self.complete = False
            self.received: list[bytes] = []

        def receive_handshake(self, record):
            self.received.append(record)
            if record == b"client-finished":
                self.complete = True

        def bytes_to_device(self):
            if len(self.received) == 1:
                return b"server-hello"
            return b""

        def status(self):
            return {"complete": self.complete, "identities": ["Client_identity"]}

    monkeypatch.setattr(goodix, "Device", FakeDevice)
    monkeypatch.setattr(tls_probe, "PSKMemoryTLSServer", FakeTLS)
    monkeypatch.setattr(
        tls_probe,
        "collect_preflight",
        lambda *args, **kwargs: {"command_path": kwargs["command_path"]},
    )

    archive = ArchiveRun.create(tmp_path, 0x27C6, 0x521D)
    manifest = tls_probe.probe_device_tls(
        archive=archive,
        vendor=0x27C6,
        product=0x521D,
        psk=b"\x00" * 32,
        reset_usb=False,
    )

    assert manifest["status"] == "ok"
    assert len(manifest["tls_records"]) == 3
    assert writes == [
        goodix.encode_message_pack(
            b"server-hello",
            goodix.FLAGS_TRANSPORT_LAYER_SECURITY,
        )
    ]
    assert json.loads(archive.manifest_path.read_text())["tls_status"]["complete"]
