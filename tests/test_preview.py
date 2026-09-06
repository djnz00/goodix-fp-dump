from unittest.mock import MagicMock, patch

from goodix_fp_dump.preview import _synthetic_frames, preview_stream


def test_preview_stream_reshapes_frames_and_stops_at_max_frames():
    frames = list(_synthetic_frames(80, 64, 3))

    set_data_shapes = []
    mock_image = MagicMock()
    mock_image.set_data.side_effect = lambda data: set_data_shapes.append(data.shape)

    with patch("goodix_fp_dump.preview.plt.imshow", return_value=mock_image) as mock_imshow, \
         patch("goodix_fp_dump.preview.plt.show"), \
         patch("goodix_fp_dump.preview.plt.draw"), \
         patch("goodix_fp_dump.preview.plt.pause"), \
         patch("goodix_fp_dump.preview.plt.ion"), \
         patch("goodix_fp_dump.preview.plt.get_fignums", return_value=[1]):
        count = preview_stream(frames, 80, 64, max_frames=3)

    assert count == 3
    assert mock_imshow.call_count == 1
    assert mock_imshow.call_args[0][0].shape == (80, 64)
    assert set_data_shapes == [(80, 64), (80, 64)]


def test_preview_stream_stops_when_window_closed():
    frames = list(_synthetic_frames(80, 64, 5))
    mock_image = MagicMock()

    with patch("goodix_fp_dump.preview.plt.imshow", return_value=mock_image), \
         patch("goodix_fp_dump.preview.plt.show"), \
         patch("goodix_fp_dump.preview.plt.draw"), \
         patch("goodix_fp_dump.preview.plt.pause"), \
         patch("goodix_fp_dump.preview.plt.ion"), \
         patch("goodix_fp_dump.preview.plt.get_fignums", return_value=[]):
        count = preview_stream(frames, 80, 64)

    assert count == 1
