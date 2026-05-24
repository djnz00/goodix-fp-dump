from __future__ import annotations

import ssl
from dataclasses import dataclass, field
from typing import Any


class InProcessTLSError(RuntimeError):
    pass


def has_psk_support() -> bool:
    return bool(getattr(ssl, "HAS_PSK", False)) and hasattr(
        ssl.SSLContext,
        "set_psk_server_callback",
    )


@dataclass(slots=True)
class PSKMemoryTLSServer:
    psk: bytes
    identity_hint: str | None = None
    cipher: str = "PSK-AES128-CBC-SHA256"
    incoming: ssl.MemoryBIO = field(default_factory=ssl.MemoryBIO, init=False)
    outgoing: ssl.MemoryBIO = field(default_factory=ssl.MemoryBIO, init=False)
    ssl_object: ssl.SSLObject = field(init=False)
    identities: list[str | None] = field(default_factory=list, init=False)
    complete: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if not has_psk_support():
            raise InProcessTLSError("Python ssl was built without PSK support")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers(self.cipher)
        context.set_psk_server_callback(self._psk_callback, self.identity_hint)
        self.ssl_object = context.wrap_bio(
            self.incoming,
            self.outgoing,
            server_side=True,
        )

    def _psk_callback(self, identity: str | None) -> bytes:
        self.identities.append(identity)
        return self.psk

    def receive_handshake(self, records: bytes = b"") -> dict[str, Any]:
        if records:
            self.incoming.write(records)
        while not self.complete:
            try:
                self.ssl_object.do_handshake()
                self.complete = True
            except ssl.SSLWantReadError:
                break
            except ssl.SSLError as error:
                raise InProcessTLSError(str(error)) from error
        return self.status()

    def bytes_to_device(self) -> bytes:
        chunks = []
        while True:
            data = self.outgoing.read()
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)

    def decrypt(self, records: bytes, size: int = 0x10000) -> bytes:
        self.incoming.write(records)
        try:
            return self.ssl_object.read(size)
        except ssl.SSLWantReadError as error:
            raise InProcessTLSError("TLS record did not contain application data") from error

    def status(self) -> dict[str, Any]:
        return {
            "complete": self.complete,
            "cipher": self.ssl_object.cipher() if self.complete else None,
            "identities": list(self.identities),
        }
