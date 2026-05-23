from __future__ import annotations

import ssl

import pytest

from goodix_fp_dump.inprocess_tls import PSKMemoryTLSServer

pytestmark = pytest.mark.unit


def test_psk_memory_tls_server_handshakes_with_python_client() -> None:
    psk = bytes.fromhex("00" * 32)
    server = PSKMemoryTLSServer(psk)
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE
    client_context.minimum_version = ssl.TLSVersion.TLSv1_2
    client_context.maximum_version = ssl.TLSVersion.TLSv1_2
    client_context.set_ciphers("PSK-AES128-CBC-SHA256")
    client_context.set_psk_client_callback(lambda hint: ("Client_identity", psk))
    client_in = ssl.MemoryBIO()
    client_out = ssl.MemoryBIO()
    client = client_context.wrap_bio(
        client_in,
        client_out,
        server_side=False,
        server_hostname=None,
    )

    for _ in range(8):
        try:
            client.do_handshake()
        except ssl.SSLWantReadError:
            pass
        server.receive_handshake(client_out.read())
        client_in.write(server.bytes_to_device())
        if server.complete:
            try:
                client.do_handshake()
            except ssl.SSLWantReadError:
                pass
            break

    assert server.status()["complete"]
    assert server.status()["identities"] == ["Client_identity"]

    client.write(b"abc")
    assert server.decrypt(client_out.read()) == b"abc"
