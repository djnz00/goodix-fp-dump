from __future__ import annotations

import pytest

import tool
from goodix_fp_dump.image import IncompleteImageError, decode_packed_image

pytestmark = pytest.mark.unit


def test_decode_image_decodes_packed_pixels() -> None:
    assert tool.decode_image(bytes([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC])) == [
        0x234,
        0x781,
        0xC56,
        0x9AB,
    ]


def test_decode_packed_image_rejects_short_buffer() -> None:
    with pytest.raises(IncompleteImageError, match="not a multiple of 6"):
        decode_packed_image(b"\x01\x02")


def test_decode_image_rejects_non_multiple_buffer() -> None:
    with pytest.raises(IncompleteImageError):
        tool.decode_image(b"\x00" * 7)


def test_write_and_read_pgm_round_trip(tmp_path) -> None:
    path = tmp_path / "image.pgm"
    image = [0, 1, 2, 3]

    tool.write_pgm(image, width=2, height=2, path=str(path))

    assert tool.read_pgm(str(path)) == (2, 2, 4095, image)
