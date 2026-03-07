from __future__ import annotations

import math

from .models import CheckResult


def clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def weighted_mean(values: list[tuple[float, float]]) -> float:
    numerator = 0.0
    denominator = 0.0
    for value, weight in values:
        numerator += value * weight
        denominator += weight
    if denominator == 0:
        return 0.0
    return numerator / denominator


def quality_gate(checks: list[CheckResult]) -> float:
    """Estimate evidence quality; low quality should favor inconclusive."""
    quality_signals: list[tuple[float, float]] = []
    for check in checks:
        if check.name == "frame_quality_shift":
            # High anomaly reduces available trust in quality-dependent checks.
            quality_signals.append((1.0 - clamp01(check.score), 1.0))
        elif check.category in {"metadata", "codec", "timing", "quality"}:
            quality_signals.append((clamp01(check.confidence), 0.6))
    return weighted_mean(quality_signals)


def fuse_scores(checks: list[CheckResult], sensitivity: float) -> tuple[float, float, str]:
    """Returns (tamper_probability, confidence, label)."""
    if not checks:
        return 0.0, 0.0, "inconclusive"

    weighted_checks: list[tuple[float, float]] = []
    for check in checks:
        # Confidence is reliability; check.score is normalized anomaly score.
        weighted_checks.append((clamp01(check.score), max(0.05, check.confidence)))
    base = weighted_mean(weighted_checks)
    gate = quality_gate(checks)

    # Use logistic scaling so mid-range evidence changes smoothly.
    bias = -2.6 + (sensitivity * 1.6)
    logit = bias + (base * 5.2) + (gate * 0.4)
    probability = 1.0 / (1.0 + math.exp(-logit))

    # Confidence depends on coverage and signal agreement.
    coverage = min(1.0, len(checks) / 6.0)
    agreement = 1.0 - abs(base - 0.5) * 0.5
    confidence = clamp01((coverage * 0.7) + (gate * 0.2) + (agreement * 0.1))

    if gate < 0.3 or confidence < 0.35:
        label = "inconclusive"
    elif probability >= 0.6:
        label = "tampered"
    elif probability >= 0.35:
        label = "suspicious"
    else:
        label = "authentic"

    return clamp01(probability), confidence, label
