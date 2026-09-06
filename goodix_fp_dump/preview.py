from __future__ import annotations

from typing import Iterable

import matplotlib.pyplot as plt
import numpy as np


def _synthetic_frames(width: int, height: int, n: int):
    base = np.arange(width * height)
    for i in range(n):
        yield ((base + i) % 4096).tolist()


def preview_stream(
    frame_iter: Iterable[list[int]],
    width: int,
    height: int,
    vmin: int = 0,
    vmax: int = 4095,
    max_frames: int | None = None,
) -> int:
    """Live-plot a stream of decoded sensor frames (flat 12-bit sample lists).

    Stops when the plot window is closed, or after max_frames if given.
    Returns the number of frames rendered.
    """
    plt.ion()
    image = None
    count = 0

    for samples in frame_iter:
        data = np.array(samples).reshape((width, height))

        if image is None:
            image = plt.imshow(data, vmin=vmin, vmax=vmax, interpolation="nearest")
            plt.show()
        else:
            if not plt.get_fignums():
                break
            image.set_data(data)
            plt.draw()

        plt.pause(0.001)
        count += 1
        if max_frames is not None and count >= max_frames:
            break

    return count


if __name__ == "__main__":
    preview_stream(_synthetic_frames(80, 64, 200), 80, 64)
