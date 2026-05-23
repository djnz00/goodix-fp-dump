from __future__ import annotations


class IncompleteImageError(ValueError):
    def __init__(self, actual: int, chunk_size: int = 6, path: str | None = None):
        self.actual = actual
        self.chunk_size = chunk_size
        self.path = path
        detail = (
            f"incomplete image buffer: {actual} bytes is not a multiple of {chunk_size}"
        )
        if path:
            detail += f" ({path})"
        super().__init__(detail)


def decode_packed_image(data: bytes, path: str | None = None) -> list[int]:
    if len(data) % 6:
        raise IncompleteImageError(len(data), path=path)

    image: list[int] = []
    for offset in range(0, len(data), 6):
        chunk = data[offset : offset + 6]
        image.append(((chunk[0] & 0xF) << 8) + chunk[1])
        image.append((chunk[3] << 4) + (chunk[0] >> 4))
        image.append(((chunk[5] & 0xF) << 8) + chunk[2])
        image.append((chunk[4] << 4) + (chunk[5] >> 4))
    return image
