from __future__ import annotations

import subprocess

import pytest

from quevidkit.models import AnalysisOptions
from quevidkit.pipeline import analyze_video


@pytest.fixture
def synthetic_video(tmp_path):
    path = str(tmp_path / "deep_analysis_source.mp4")
    subprocess.run(
        [
            "ffmpeg",
            "-y",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=320x180:rate=24",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:sample_rate=44100",
            "-t",
            "6",
            "-pix_fmt",
            "yuv420p",
            "-c:a",
            "aac",
            "-shortest",
            path,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return path


def test_analyze_video_deep_preset_wires_all_19_checks(synthetic_video):
    opts = AnalysisOptions(preset="deep", enable_advanced_forensics=True)
    result = analyze_video(synthetic_video, opts)

    check_names = [c.name for c in result.checks]

    assert len(result.checks) == 19, f"expected exactly 19 checks, got {len(result.checks)}: {check_names}"
    assert len(check_names) == len(set(check_names)), f"duplicate check names found: {check_names}"

    for expected_name in (
        "sensor_noise_correlation",
        "frequency_artifact_scan",
        "provenance_manifest",
        "container_edit_trace",
    ):
        assert expected_name in check_names, f"{expected_name} missing from checks: {check_names}"

    assert result.label in {"authentic", "suspicious", "tampered", "inconclusive"}
    assert 0.0 <= result.tamper_probability <= 1.0
    assert 0.0 <= result.confidence <= 1.0

    for check in result.checks:
        assert 0.0 <= check.score <= 1.0, f"{check.name} score out of range: {check.score}"
        assert 0.0 <= check.confidence <= 1.0, f"{check.name} confidence out of range: {check.confidence}"
