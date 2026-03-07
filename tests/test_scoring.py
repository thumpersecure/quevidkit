from quevidkit.models import CheckResult
from quevidkit.scoring import clamp01, fuse_scores


def test_clamp01_bounds():
    assert clamp01(-1.0) == 0.0
    assert clamp01(2.0) == 1.0
    assert clamp01(0.42) == 0.42


def test_fuse_scores_detects_tampered():
    checks = [
        CheckResult(
            name="packet_timing_anomalies",
            category="timing",
            score=0.92,
            confidence=0.9,
            summary="timing anomalies",
        ),
        CheckResult(
            name="frame_structure_anomalies",
            category="codec",
            score=0.81,
            confidence=0.8,
            summary="codec anomalies",
        ),
        CheckResult(
            name="frame_quality_shift",
            category="quality",
            score=0.66,
            confidence=0.86,
            summary="quality shifts",
        ),
    ]
    probability, confidence, label = fuse_scores(checks, sensitivity=0.7)
    assert probability > 0.6
    assert confidence > 0.3
    assert label in {"tampered", "suspicious"}


def test_fuse_scores_authentic_path():
    checks = [
        CheckResult(name="metadata", category="metadata", score=0.03, confidence=0.9, summary="ok"),
        CheckResult(name="timing", category="timing", score=0.04, confidence=0.8, summary="ok"),
        CheckResult(name="quality", category="quality", score=0.05, confidence=0.75, summary="ok"),
    ]
    probability, confidence, label = fuse_scores(checks, sensitivity=0.7)
    assert probability < 0.35
    assert confidence > 0.3
    assert label in {"authentic", "inconclusive"}
