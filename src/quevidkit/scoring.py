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
        if check.name in ("frame_quality_shift", "ela_frame_analysis"):
            # High anomaly reduces available trust in quality-dependent checks.
            quality_signals.append((1.0 - clamp01(check.score), 1.0))
        elif check.category in {"metadata", "codec", "timing", "quality", "audio"}:
            quality_signals.append((clamp01(check.confidence), 0.6))
    return weighted_mean(quality_signals)


def _corroboration_factor(checks: list[CheckResult]) -> float:
    """Measure how many independent forensic categories agree on anomalies.

    Returns a factor between 0.0 and 1.0:
    - 0.0: no checks flagged anything
    - Low: only one category flagged (possible false positive)
    - High: multiple independent categories agree (strong evidence)
    """
    flagged_categories: set[str] = set()
    for check in checks:
        if check.score >= 0.25 and check.confidence >= 0.35:
            flagged_categories.add(check.category)

    n = len(flagged_categories)
    if n == 0:
        return 0.0
    if n == 1:
        return 0.4  # lone-wolf: penalize
    if n == 2:
        return 0.7
    return min(1.0, 0.7 + n * 0.1)  # 3+ categories: strong corroboration


def _lone_wolf_penalty(checks: list[CheckResult]) -> float:
    """If only a single check is driving the score, apply a penalty.

    A single high-scoring check with all others clean is more likely a false
    positive than a genuine tampering event. Real tampering usually leaves
    traces in multiple independent forensic domains.
    """
    high_checks = [c for c in checks if c.score >= 0.35 and c.confidence >= 0.3]
    low_checks = [c for c in checks if c.score < 0.15 and c.confidence >= 0.3]

    if len(high_checks) == 1 and len(low_checks) >= 3:
        # One check is high, at least 3 others are clean — this is suspicious of FP
        return 0.55  # reduce probability by multiplying
    if len(high_checks) == 1 and len(low_checks) >= 2:
        return 0.70
    return 1.0  # no penalty


def fuse_scores(checks: list[CheckResult], sensitivity: float) -> tuple[float, float, str]:
    """Returns (tamper_probability, confidence, label)."""
    if not checks:
        return 0.5, 0.0, "inconclusive"

    weighted_checks: list[tuple[float, float]] = []
    for check in checks:
        # Confidence is reliability; check.score is normalized anomaly score.
        weighted_checks.append((clamp01(check.score), max(0.05, check.confidence)))
    base = weighted_mean(weighted_checks)
    gate = quality_gate(checks)

    # Corroboration: require multiple categories to agree for high probability
    corr = _corroboration_factor(checks)
    lone_penalty = _lone_wolf_penalty(checks)

    # Logistic function: bias shifts the decision threshold based on sensitivity
    # Raised base bias from -2.6 to -3.0 to reduce false positives overall
    bias = -3.0 + (sensitivity * 1.6)
    logit = bias + (base * 5.2) + (gate * 0.4) + (corr * 1.0)
    probability = 1.0 / (1.0 + math.exp(-logit))

    # Apply lone-wolf penalty
    probability *= lone_penalty

    # Confidence depends on coverage and signal agreement.
    coverage = min(1.0, len(checks) / 15.0)  # updated from 11 to 15 (more checks now)
    agreement = 1.0 - abs(base - 0.5) * 0.5
    confidence = clamp01((coverage * 0.6) + (gate * 0.2) + (agreement * 0.1) + (corr * 0.1))

    if gate < 0.3 or confidence < 0.35:
        label = "inconclusive"
    elif probability >= 0.65:  # raised from 0.6
        label = "tampered"
    elif probability >= 0.38:  # raised from 0.35
        label = "suspicious"
    else:
        label = "authentic"

    return clamp01(probability), confidence, label
