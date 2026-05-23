from __future__ import annotations

import socket
import subprocess

import pytest

from goodix_fp_dump.tls_proxy import PortInUseError, TLSServer, port_available

pytestmark = pytest.mark.unit


class FakeProcess:
    stdout = object()

    def __init__(self):
        self.killed = False
        self.terminated = False
        self.communicate_calls = 0

    def poll(self):
        return None

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

    def communicate(self, timeout=None):
        self.communicate_calls += 1
        if self.communicate_calls == 1:
            raise subprocess.TimeoutExpired(["openssl"], timeout)
        return b"tail", None


def test_port_available_detects_bound_port() -> None:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

        assert not port_available("127.0.0.1", port)


def test_tls_server_rejects_stale_port() -> None:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

        with pytest.raises(PortInUseError):
            TLSServer("00", port=port).start()


def test_tls_server_kills_after_terminate_timeout() -> None:
    server = TLSServer("00")
    process = FakeProcess()
    server.process = process

    assert server.stop(timeout=0.01) == b"tail"
    assert process.terminated
    assert process.killed
    assert process.communicate_calls == 2
