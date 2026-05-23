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
