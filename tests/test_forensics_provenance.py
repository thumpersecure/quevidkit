from __future__ import annotations

import os
import subprocess
import wave

import pytest

from quevidkit.ffprobe_utils import build_basic_probe
from quevidkit.forensics_provenance import (
    container_edit_trace_checks,
    provenance_manifest_checks,
)


def _make_plain_mp4(path: str, duration_s: float = 2.0) -> None:
    subprocess.run(
        [
            "ffmpeg",
            "-y",
            "-f",
            "lavfi",
            "-i",
            f"testsrc=size=320x180:rate=24",
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
def plain_mp4(tmp_path):
    path = str(tmp_path / "plain.mp4")
    _make_plain_mp4(path)
    return path


@pytest.fixture
def plain_mp4_probe(plain_mp4):
    return build_basic_probe(plain_mp4)


@pytest.fixture
def tiny_wav(tmp_path):
    """A tiny valid WAV file — not an ISO-BMFF container at all."""
    path = str(tmp_path / "tiny.wav")
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(8000)
        w.writeframes(b"\x00\x01" * 100)
    return path


@pytest.fixture
def random_bytes_file(tmp_path):
    path = str(tmp_path / "random.bin")
    with open(path, "wb") as f:
        f.write(os.urandom(2048))
    return path


# ── provenance_manifest_checks ────────────────────────────────────────────────


def test_provenance_manifest_valid_result_shape(plain_mp4, plain_mp4_probe):
    result = provenance_manifest_checks(plain_mp4, plain_mp4_probe)
    assert result.name == "provenance_manifest"
    assert result.category == "metadata"
    assert 0.0 <= result.score <= 1.0
    assert 0.0 <= result.confidence <= 1.0
    assert isinstance(result.summary, str) and result.summary


def test_provenance_manifest_no_markers_is_low_score_absence_path(plain_mp4, plain_mp4_probe):
    """A plain synthetic MP4 with no C2PA/JUMBF/XMP markers should hit the
    'absence is not evidence of tampering' branch: score=0.08, confidence=0.3
    per the exact literals in forensics_provenance.py's else branch.
    """
    result = provenance_manifest_checks(plain_mp4, plain_mp4_probe)
    assert result.score < 0.15
    assert result.score == pytest.approx(0.08)
    assert result.confidence == pytest.approx(0.3)
    assert "No C2PA/JUMBF or XMP provenance metadata found" in result.summary
    assert "NOT itself" in result.summary
    assert result.details["jumbf_or_c2pa_signature_found"] is False
    assert result.details["xmp_packet_found"] is False
    assert result.details["format_tag_provenance_hits"] == []


def test_provenance_manifest_nonexistent_file_degrades_gracefully():
    result = provenance_manifest_checks("/tmp/does-not-exist-quevidkit-prov-12345.mp4", {})
    assert result.name == "provenance_manifest"
    assert result.score == 0.0
    assert result.confidence <= 0.1
    assert 0.0 <= result.confidence <= 1.0


def test_provenance_manifest_detects_xmp_packet(tmp_path):
    """Synthesize a file containing an XMP packet marker directly (no ffmpeg
    dependency needed here since the function just byte-scans the file).
    """
    path = str(tmp_path / "fake_xmp.mp4")
    blob = b"\x00\x00\x00\x18ftypmp42" + b"junk padding " * 20
    blob += b"<?xpacket begin='' id='W5M0MpCehiHzreSzNTczkc9d'?> some xmp content adobe premiere "
    blob += b"padding" * 50
    with open(path, "wb") as f:
        f.write(blob)
    result = provenance_manifest_checks(path, {})
    assert result.details["xmp_packet_found"] is True
    assert "adobe premiere" in result.details["xmp_edit_tool_markers"]
    assert result.score == pytest.approx(0.12)
    assert result.confidence == pytest.approx(0.4)


def test_provenance_manifest_detects_c2pa_jumbf_marker(tmp_path):
    path = str(tmp_path / "fake_c2pa.mp4")
    blob = b"\x00\x00\x00\x18ftypmp42" + b"junk padding jumb c2pa manifest bytes " * 10
    with open(path, "wb") as f:
        f.write(blob)
    result = provenance_manifest_checks(path, {})
    assert result.details["jumbf_or_c2pa_signature_found"] is True
    assert result.score == pytest.approx(0.05)
    assert result.confidence == pytest.approx(0.5)
    assert "positive provenance signal" in result.summary


# ── container_edit_trace_checks ───────────────────────────────────────────────


def test_container_edit_trace_valid_result_shape(plain_mp4, plain_mp4_probe):
    result = container_edit_trace_checks(plain_mp4, plain_mp4_probe)
    assert result.name == "container_edit_trace"
    assert result.category == "metadata"
    assert 0.0 <= result.score <= 1.0
    assert 0.0 <= result.confidence <= 1.0
    assert isinstance(result.summary, str) and result.summary


def test_container_edit_trace_real_mp4_low_or_no_findings(plain_mp4, plain_mp4_probe):
    result = container_edit_trace_checks(plain_mp4, plain_mp4_probe)
    assert result.details["top_level_box_count"] > 0
    assert result.details["recognized_box_ratio"] >= 0.5
    # A plain single-pass ffmpeg export should not trip the heavier findings.
    assert result.score <= 0.3


def test_container_edit_trace_nonexistent_file_degrades_gracefully():
    result = container_edit_trace_checks("/tmp/does-not-exist-quevidkit-container-12345.mp4", {})
    assert result.name == "container_edit_trace"
    assert result.score == 0.0
    assert result.confidence <= 0.1
    assert 0.0 <= result.confidence <= 1.0


def test_container_edit_trace_non_isobmff_bails_out_gracefully_wav(tiny_wav):
    # basic_probe format_name deliberately omitted/empty to force reliance on
    # the raw-byte-sniff fallback path (looks_like_isobmff).
    result = container_edit_trace_checks(tiny_wav, {"format": {"format_name": "wav"}})
    assert result.name == "container_edit_trace"
    assert result.score == 0.0
    assert result.confidence <= 0.2
    assert "not ISO-BMFF" in result.summary


def test_container_edit_trace_non_isobmff_bails_out_gracefully_random_bytes(random_bytes_file):
    result = container_edit_trace_checks(random_bytes_file, {})
    assert result.name == "container_edit_trace"
    assert result.score == 0.0
    assert 0.0 <= result.confidence <= 1.0
    # Random bytes are extremely unlikely to parse as a well-formed box chain
    # matching >=50% recognized top-level box types, so this should land in
    # one of the graceful bailout branches rather than raising.
