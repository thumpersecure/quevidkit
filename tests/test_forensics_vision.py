from __future__ import annotations

import subprocess

import pytest

from quevidkit.forensics_vision import (
    frequency_artifact_checks,
    sensor_noise_correlation_checks,
)
from quevidkit.models import AnalysisOptions


def _make_video(path: str, duration_s: float, source: str = "testsrc", size: str = "320x180", rate: int = 24) -> None:
    subprocess.run(
        [
            "ffmpeg",
            "-y",
            "-f",
            "lavfi",
            "-i",
            f"{source}=size={size}:rate={rate}",
            "-t",
            str(duration_s),
            "-pix_fmt",
            "yuv420p",
            path,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


@pytest.fixture
def short_video(tmp_path):
    """~0.5s video: far too few sampled frames for either check's minimum threshold."""
    path = str(tmp_path / "short.mp4")
    _make_video(path, duration_s=0.5)
    return path


@pytest.fixture
def long_video(tmp_path):
    """~5s testsrc video: plenty of frames for both checks to run end-to-end."""
    path = str(tmp_path / "long.mp4")
    _make_video(path, duration_s=5.0, source="testsrc2", rate=24)
    return path


@pytest.fixture
def mandelbrot_video(tmp_path):
    """A different synthetic generator for variety / distinct visual content."""
    path = str(tmp_path / "mandelbrot.mp4")
    _make_video(path, duration_s=5.0, source="mandelbrot", size="320x180", rate=24)
    return path


def _default_options(preset: str = "deep") -> AnalysisOptions:
    opts = AnalysisOptions(preset=preset)
    opts.apply_preset()
    return opts


# ── sensor_noise_correlation_checks ───────────────────────────────────────────


def test_sensor_noise_correlation_valid_result_shape(long_video):
    opts = _default_options()
    result = sensor_noise_correlation_checks(long_video, duration_s=5.0, fps_hint=24.0, options=opts)
    assert result.name == "sensor_noise_correlation"
    assert result.category == "quality"
    assert 0.0 <= result.score <= 1.0
    assert 0.0 <= result.confidence <= 1.0
    assert isinstance(result.summary, str) and result.summary
    assert "sampled_frames" in result.details


def test_sensor_noise_correlation_enough_frames_runs_end_to_end(long_video):
    opts = _default_options()
    result = sensor_noise_correlation_checks(long_video, duration_s=5.0, fps_hint=24.0, options=opts)
    # 5s @ deep preset sample_fps (>=4.0) should comfortably clear the 10-frame minimum.
    assert result.details["sampled_frames"] >= 10
    assert result.confidence > 0.1
    assert "windows" in result.details
    assert result.details["windows"] >= 2
    assert "min_correlation" in result.details
    assert "window_pair_correlations" in result.details


def test_sensor_noise_correlation_too_few_frames_returns_graceful_zero(short_video):
    # Use a low sample_fps + fast preset so a 0.5s clip yields < 10 sampled frames.
    opts = AnalysisOptions(preset="fast", sample_fps=1.0, max_frames=900)
    opts.apply_preset()
    result = sensor_noise_correlation_checks(short_video, duration_s=0.5, fps_hint=24.0, options=opts)
    assert result.score == 0.0
    assert result.confidence <= 0.15
    assert "sampled_frames" in result.details


def test_sensor_noise_correlation_nonexistent_file_degrades_gracefully():
    opts = _default_options()
    result = sensor_noise_correlation_checks(
        "/tmp/does-not-exist-quevidkit-test-12345.mp4", duration_s=5.0, fps_hint=24.0, options=opts
    )
    assert result.name == "sensor_noise_correlation"
    assert result.score == 0.0
    assert result.confidence <= 0.15
    assert 0.0 <= result.confidence <= 1.0


# ── frequency_artifact_checks ─────────────────────────────────────────────────


def test_frequency_artifact_valid_result_shape(long_video):
    opts = _default_options()
    result = frequency_artifact_checks(long_video, duration_s=5.0, fps_hint=24.0, options=opts)
    assert result.name == "frequency_artifact_scan"
    assert result.category == "quality"
    assert 0.0 <= result.score <= 1.0
    assert 0.0 <= result.confidence <= 1.0
    assert isinstance(result.summary, str) and result.summary
    assert "method" in result.details
    assert "disclaimer" in result.details


def test_frequency_artifact_enough_frames_runs_end_to_end(mandelbrot_video):
    opts = _default_options()
    result = frequency_artifact_checks(mandelbrot_video, duration_s=5.0, fps_hint=24.0, options=opts)
    assert result.details["sampled_frames"] >= 8
    assert result.details["fft_frames_analyzed"] >= 5
    assert result.details["mean_spectral_peak_ratio"] is not None
    assert "face_flicker_component_score" in result.details
    assert "face_frames_used" in result.details


def test_frequency_artifact_too_few_frames_returns_graceful_zero(short_video):
    opts = AnalysisOptions(preset="fast", sample_fps=1.0, max_frames=900)
    opts.apply_preset()
    result = frequency_artifact_checks(short_video, duration_s=0.5, fps_hint=24.0, options=opts)
    assert result.score == 0.0
    assert result.confidence <= 0.15
    assert "sampled_frames" in result.details


def test_frequency_artifact_nonexistent_file_degrades_gracefully():
    opts = _default_options()
    result = frequency_artifact_checks(
        "/tmp/does-not-exist-quevidkit-test-67890.mp4", duration_s=5.0, fps_hint=24.0, options=opts
    )
    assert result.name == "frequency_artifact_scan"
    assert result.score == 0.0
    assert result.confidence <= 0.15
    assert 0.0 <= result.confidence <= 1.0
