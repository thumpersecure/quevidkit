from __future__ import annotations

import subprocess

import numpy as np
import pytest

from quevidkit.pipeline import AnalysisOptions, _compute_blockiness, opencv_frame_quality_checks


def _make_clip(path: str, size: str) -> None:
    subprocess.run(
        ["ffmpeg", "-y", "-f", "lavfi", "-i", f"testsrc2=size={size}:rate=24",
         "-t", "3", "-pix_fmt", "yuv420p", path],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )


@pytest.mark.parametrize("shape", [(180, 320), (180, 321), (181, 320), (17, 17), (180, 319)])
def test_blockiness_handles_any_frame_shape(shape):
    # Regression: 320-wide frames made gray[:, 7::8] (40 cols) and gray[:, 8::8]
    # (39 cols) un-broadcastable, so the check failed on every video.
    frame = (np.random.default_rng(0).random(shape) * 255).astype("uint8")
    assert _compute_blockiness(frame) >= 0.0


def test_blockiness_detects_8x8_grid():
    flat = np.full((180, 320), 100, dtype="uint8")
    blocky = flat.copy()
    for x in range(0, 320, 8):
        blocky[:, x:x + 8] = 100 + (x // 8 % 2) * 20
    assert _compute_blockiness(blocky) > _compute_blockiness(flat)


@pytest.mark.parametrize("size", ["320x180", "321x181", "641x359"])
def test_frame_quality_check_runs_on_real_clips(tmp_path, size):
    path = str(tmp_path / "clip.mp4")
    _make_clip(path, size)
    result = opencv_frame_quality_checks(path, 3.0, 24.0, AnalysisOptions(sample_fps=4))
    assert result.name == "frame_quality_shift"
    assert "sampled_frames" in result.details  # full path ran, no skip/exception
    assert result.details["sampled_frames"] > 1
