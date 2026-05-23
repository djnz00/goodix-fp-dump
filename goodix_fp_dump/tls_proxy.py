from __future__ import annotations

import socket
import subprocess
import time
from dataclasses import dataclass, field
from typing import BinaryIO


class TLSServerError(RuntimeError):
    pass


class PortInUseError(TLSServerError):
    pass


@dataclass(slots=True)
class TLSServer:
    psk: str
    port: int = 4433
    bind: str = "127.0.0.1"
    openssl: str = "openssl"
    startup_timeout: float = 2.0
    process: subprocess.Popen | None = field(default=None, init=False)
    transcript: bytes = field(default=b"", init=False)

    def start(self) -> "TLSServer":
        if not port_available(self.bind, self.port):
            raise PortInUseError(f"TLS port already in use: {self.bind}:{self.port}")

        self.process = subprocess.Popen(
            [
                self.openssl,
                "s_server",
                "-nocert",
                "-psk",
                self.psk,
                "-accept",
                f"{self.bind}:{self.port}",
                "-quiet",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + self.startup_timeout
        while port_available(self.bind, self.port):
            if self.process.poll() is not None:
                output = b""
                if self.process.stdout is not None:
                    output = self.process.stdout.read() or b""
                self.transcript += output
                self.process = None
                raise TLSServerError("TLS server exited before accepting connections")
            if time.monotonic() >= deadline:
                self.stop()
                raise TLSServerError(
                    f"TLS server did not bind {self.bind}:{self.port}"
                )
            time.sleep(0.02)
        return self

    @property
    def stdout(self) -> BinaryIO:
        if self.process is None or self.process.stdout is None:
            raise TLSServerError("TLS server is not running")
        return self.process.stdout

    def stop(self, timeout: float = 2) -> bytes:
        if self.process is None:
            return self.transcript

        if self.process.poll() is None:
            self.process.terminate()

        try:
            stdout, _ = self.process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            stdout, _ = self.process.communicate()

        if stdout:
            self.transcript += stdout
        self.process = None
        return self.transcript

    def __enter__(self) -> "TLSServer":
        return self.start()

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.stop()


def port_available(host: str, port: int) -> bool:
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True
