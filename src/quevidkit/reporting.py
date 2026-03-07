from __future__ import annotations

import html

from .models import AnalysisResult


def decision_color(label: str) -> str:
    if label == "tampered":
        return "#b00020"
    if label == "suspicious":
        return "#cc6600"
    if label == "authentic":
        return "#1f7a1f"
    return "#555555"


def _check_long_explanation(check_name: str, summary: str) -> str:
    mapping = {
        "metadata_codec_consistency": (
            "This check compares container and stream metadata for signs of suspicious edits, "
            "such as mismatched durations, unusual bitrate declarations, and metadata rewriting."
        ),
        "packet_timing_anomalies": (
            "This check inspects packet timestamp continuity. Large timing discontinuities can indicate "
            "splicing, frame removal, or timeline reconstruction."
        ),
        "frame_structure_anomalies": (
            "This check looks for structural codec changes across frames, including irregular GOP patterns, "
            "resolution switches, or color profile changes that often appear after tampering."
        ),
        "frame_quality_shift": (
            "This check measures abrupt visual quality changes across time, including blur shifts, blockiness "
            "changes, and repeated/omitted frame behavior."
        ),
    }
    prefix = mapping.get(
        check_name,
        "This forensic check contributes to the final decision by measuring anomaly strength and reliability.",
    )
    return f"{prefix} Detector summary: {summary}"


def _score_band(score: float) -> str:
    if score >= 0.75:
        return "High anomaly signal"
    if score >= 0.45:
        return "Moderate anomaly signal"
    if score >= 0.2:
        return "Low anomaly signal"
    return "Minimal anomaly signal"


def _timeline_blocks(result: AnalysisResult) -> str:
    if not result.suspicious_segments:
        return '<div class="timeline-empty">No suspicious segments were detected.</div>'
    duration = max(result.duration_s, max((segment.end_s for segment in result.suspicious_segments), default=0.0), 1.0)
    blocks = []
    for index, segment in enumerate(result.suspicious_segments[:120]):
        start_ratio = max(0.0, min(1.0, segment.start_s / duration))
        end_ratio = max(start_ratio, min(1.0, segment.end_s / duration))
        width_ratio = max(0.004, end_ratio - start_ratio)
        blocks.append(
            '<div class="timeline-block" '
            f'style="left:{start_ratio * 100:.2f}%;width:{width_ratio * 100:.2f}%;" '
            f'title="{html.escape(segment.category)} | {segment.start_s:.2f}s - {segment.end_s:.2f}s | confidence {segment.confidence:.2f}"></div>'
        )
        if index > 118:
            break
    return f'<div class="timeline-track">{"".join(blocks)}</div>'


def result_to_html(result: AnalysisResult) -> str:
    checks_html = []
    for check in result.checks:
        score_percent = max(0.0, min(100.0, check.score * 100.0))
        confidence_percent = max(0.0, min(100.0, check.confidence * 100.0))
        checks_html.append(
            '<div class="check-card">'
            f"<h3>{html.escape(check.name)}</h3>"
            f"<p class='check-sub'>{html.escape(_score_band(check.score))}</p>"
            '<div class="bar-row"><span>Anomaly score</span>'
            f'<div class="bar"><div class="bar-fill score" style="width:{score_percent:.1f}%"></div></div>'
            f"<strong>{score_percent:.1f}%</strong></div>"
            '<div class="bar-row"><span>Evidence confidence</span>'
            f'<div class="bar"><div class="bar-fill conf" style="width:{confidence_percent:.1f}%"></div></div>'
            f"<strong>{confidence_percent:.1f}%</strong></div>"
            f"<p>{html.escape(_check_long_explanation(check.name, check.summary))}</p>"
            "</div>"
        )
    segments_html = "".join(
        f"<li><strong>{html.escape(segment.category)}</strong>: {segment.start_s:.2f}s to {segment.end_s:.2f}s "
        f"(confidence {segment.confidence:.2f})</li>"
        for segment in result.suspicious_segments[:20]
    )
    explanation = "".join(f"<li>{html.escape(line)}</li>" for line in result.explanation) or "<li>No additional explanation.</li>"
    risk_percent = max(0.0, min(100.0, result.tamper_probability * 100.0))
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>quevidkit forensic report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #111; background: #f5f6fa; }}
    .header {{ margin-bottom: 18px; }}
    .badge {{ display: inline-block; padding: 6px 12px; border-radius: 16px; color: white; font-weight: bold; }}
    .card {{ background: white; border: 1px solid #e2e2e2; border-radius: 8px; padding: 16px; margin-bottom: 16px; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(3, minmax(150px, 1fr)); gap: 12px; margin-top: 12px; }}
    .summary-box {{ border: 1px solid #ececec; border-radius: 8px; padding: 10px; background: #fcfcfd; }}
    .summary-box p {{ margin: 0; font-size: 0.9rem; color: #555; }}
    .summary-box h3 {{ margin: 6px 0 0; font-size: 1.2rem; }}
    .meter {{ margin-top: 10px; height: 16px; border-radius: 20px; background: #eceef4; overflow: hidden; }}
    .meter-fill {{ height: 100%; background: linear-gradient(90deg, #1f7a1f 0%, #cc6600 60%, #b00020 100%); }}
    .checks-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; }}
    .check-card {{ border: 1px solid #e7e8ee; border-radius: 8px; padding: 12px; background: #fff; }}
    .check-sub {{ margin: 0 0 8px; color: #5c5f69; font-size: 0.92rem; }}
    .bar-row {{ display: grid; grid-template-columns: 130px 1fr auto; gap: 8px; align-items: center; margin: 6px 0; font-size: 0.88rem; }}
    .bar {{ height: 10px; border-radius: 20px; background: #eceff6; overflow: hidden; }}
    .bar-fill {{ height: 100%; }}
    .bar-fill.score {{ background: #b00020; }}
    .bar-fill.conf {{ background: #1a4fd8; }}
    .timeline-track {{ position: relative; height: 30px; border-radius: 8px; background: #edf0f8; border: 1px solid #dce1ef; }}
    .timeline-block {{ position: absolute; top: 3px; height: 24px; background: #b00020; border-radius: 6px; opacity: 0.75; }}
    .timeline-empty {{ color: #666; font-style: italic; }}
    ul {{ margin-top: 8px; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>quevidkit forensic report</h1>
    <p>This report converts machine JSON findings into a human-friendly investigation summary.</p>
  </div>
  <div class="card">
    <div class="badge" style="background:{decision_color(result.label)}">{html.escape(result.label.upper())}</div>
    <div class="summary-grid">
      <div class="summary-box"><p>Tamper probability</p><h3>{risk_percent:.1f}%</h3></div>
      <div class="summary-box"><p>Evidence confidence</p><h3>{result.confidence * 100:.1f}%</h3></div>
      <div class="summary-box"><p>Duration</p><h3>{result.duration_s:.2f}s</h3></div>
    </div>
    <div class="meter"><div class="meter-fill" style="width:{risk_percent:.1f}%"></div></div>
    <p><strong>Video:</strong> {html.escape(result.video_path)}</p>
    <p><strong>SHA256:</strong> {html.escape(result.file_sha256)}</p>
  </div>
  <div class="card">
    <h2>Plain-language conclusion</h2>
    <ul>{explanation}</ul>
  </div>
  <div class="card">
    <h2>Evidence strength by forensic check</h2>
    <div class="checks-grid">
      {''.join(checks_html) or '<p>No checks were available.</p>'}
    </div>
  </div>
  <div class="card">
    <h2>Timeline of suspicious segments</h2>
    {_timeline_blocks(result)}
    <ul>{segments_html or '<li>None</li>'}</ul>
  </div>
</body>
</html>
"""
