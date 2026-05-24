from __future__ import annotations

import pytest

import goodix

pytestmark = pytest.mark.unit


def test_command_round_trip() -> None:
    command = goodix.encode_command(0xA, 0x5)

    assert command == 0xAA
    assert goodix.decode_command(command) == (0xA, 0x5)


def test_decode_rejects_invalid_command() -> None:
    with pytest.raises(ValueError, match="Invalid command"):
        goodix.decode_command(0x01)


def test_message_pack_round_trip() -> None:
    payload = b"\x01\x02\x03"
    packed = goodix.encode_message_pack(payload)

    assert goodix.check_message_pack(packed) == payload


def test_message_pack_rejects_bad_checksum() -> None:
    packed = bytearray(goodix.encode_message_pack(b"\x01\x02"))
    packed[3] ^= 0xFF

    with pytest.raises(ValueError, match="Invalid data"):
        goodix.check_message_pack(bytes(packed))


def test_message_protocol_round_trip() -> None:
    payload = b"\x11\x22"
    encoded = goodix.encode_message_protocol(payload, goodix.COMMAND_NOP)

    assert goodix.check_message_protocol(encoded, goodix.COMMAND_NOP) == payload


def test_message_protocol_without_checksum_round_trip() -> None:
    payload = b"\x00\x00\x00\x00"
    encoded = goodix.encode_message_protocol(
        payload,
        goodix.COMMAND_NOP,
        checksum=False,
    )

    assert (
        goodix.check_message_protocol(
            encoded,
            goodix.COMMAND_NOP,
            checksum=False,
        )
        == payload
    )


def test_ack_round_trip() -> None:
    assert goodix.check_ack(bytes([goodix.COMMAND_NOP, 0x03]), goodix.COMMAND_NOP)


def test_ack_rejects_wrong_command() -> None:
    with pytest.raises(ValueError, match="Invalid ack"):
        goodix.check_ack(bytes([goodix.COMMAND_RESET, 0x03]), goodix.COMMAND_NOP)


def test_windows_tls_connection_command_frame() -> None:
    frame = goodix.encode_message_pack(
        goodix.encode_message_protocol(
            b"\x00\x00",
            goodix.COMMAND_REQUEST_TLS_CONNECTION,
        )
    )

    assert frame == bytes.fromhex("a00600a6d003000000d7")
    assert (
        goodix.check_message_protocol(
            goodix.check_message_pack(frame),
            goodix.COMMAND_REQUEST_TLS_CONNECTION,
        )
        == b"\x00\x00"
    )


def test_windows_image_command_frame_uses_0x20_with_dac_payload() -> None:
    payload = bytes.fromhex("4503a700a100a700a300")
    frame = goodix.encode_message_pack(
        goodix.encode_message_protocol(
            payload,
            goodix.COMMAND_MCU_GET_IMAGE,
        )
    )

    assert frame == bytes.fromhex("a00e00ae200b004503a700a100a700a300a5")
    assert (
        goodix.check_message_protocol(
            goodix.check_message_pack(frame),
            goodix.COMMAND_MCU_GET_IMAGE,
        )
        == payload
    )
