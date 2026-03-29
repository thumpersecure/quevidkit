from __future__ import annotations

import html

from .models import AnalysisResult


def decision_color(label: str) -> str:
    if label == "tampered":
        return "#ff5a6b"
    if label == "suspicious":
        return "#f6b73c"
    if label == "authentic":
        return "#3dd68c"
    return "#6f7d97"


def _check_long_explanation(check_name: str, summary: str) -> str:
    mapping = {
        "metadata_codec_consistency": (
            "Compares container and stream metadata (durations, bitrates, format tags) for consistency. "
            "Mismatches can indicate re-muxing or editing, but minor drift is common after legitimate re-encoding."
        ),
        "packet_timing_anomalies": (
            "Inspects packet timestamp continuity for gaps or non-monotonic sequences. "
            "Large discontinuities may indicate splicing, but VFR cameras and screen captures commonly produce irregular timing."
        ),
        "frame_structure_anomalies": (
            "Analyzes GOP regularity, resolution consistency, and color profile stability. "
            "Irregular patterns may indicate concatenation from different sources, but adaptive encoding intentionally varies GOP structure."
        ),
        "frame_quality_shift": (
            "Measures abrupt visual quality changes (blur, blockiness, duplicate frames). "
            "Discontinuities may indicate inserted content, but scene changes and focus shifts cause legitimate quality variation."
        ),
        "compression_consistency": (
            "Compares packet-size distributions across timeline segments per frame type. "
            "Shifts may indicate re-encoding of a portion, but VBR encoding and scene complexity naturally cause variation."
        ),
        "scene_cut_forensics": (
            "Correlates scene transitions with GOP/keyframe structure. "
            "Misaligned cuts may indicate splicing, but scene-based encoding and variable GOP modes produce legitimate misalignment."
        ),
        "audio_spectral_continuity": (
            "Detects abrupt spectral discontinuities in audio (energy, frequency content). "
            "Sharp breaks may indicate audio splicing, but sudden sounds and environment changes are legitimate causes."
        ),
        "temporal_noise_consistency": (
            "Measures per-frame noise levels to detect source changes. "
            "Noise floor shifts may indicate different cameras/encoders, but lighting changes and auto-ISO naturally alter noise."
        ),
        "double_compression_detection": (
            "Detects periodic fingerprints from prior encoding in frame-size autocorrelation. "
            "Strong evidence of re-encoding, but social media upload and messaging compression routinely re-encode without tampering."
        ),
        "ela_frame_analysis": (
            "Error Level Analysis: re-compresses frames and measures residuals. "
            "Different residual levels may indicate mixed compression, but complex textures naturally produce higher ELA variation."
        ),
        "bitstream_structure": (
            "Checks for mid-stream codec parameter changes (color space, interlacing, frame-type distributions). "
            "Parameter switches strongly indicate concatenation, but some broadcast formats legitimately change parameters."
        ),
        "qp_consistency": (
            "Analyzes GOP frame-type patterns for consistency across the timeline. "
            "Pattern changes indicate different encoding sessions, but scene-based encoding intentionally varies patterns."
        ),
        "thumbnail_mismatch": (
            "Compares the embedded thumbnail image against the actual first frame. "
            "A mismatch suggests post-recording editing, but some platforms set thumbnails from mid-video keyframes."
        ),
        "av_sync_drift": (
            "Measures audio-video timing offset at checkpoints across the timeline. "
            "Jumps or progressive drift may indicate splicing, but VFR recording and streaming protocols introduce minor offsets."
        ),
        "bitrate_distribution": (
            "Tests whether packet-size distribution is unimodal (single source) or bimodal (mixed sources). "
            "Bimodality suggests spliced content, but highly variable content and VBR encoding can appear somewhat bimodal."
        ),
    }
    prefix = mapping.get(
        check_name,
        "This forensic check contributes to the final decision by measuring anomaly strength and reliability.",
    )
    return f"{prefix} Result: {summary}"


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
    body {{ font-family: Arial, sans-serif; margin: 0; padding: 24px; color: #edf4ff; background: radial-gradient(circle at top, #18253e 0%, #08111f 62%, #050914 100%); }}
    .shell {{ max-width: 1120px; margin: 0 auto; }}
    .header {{ margin-bottom: 18px; }}
    .eyebrow {{ text-transform: uppercase; letter-spacing: 0.18em; color: #8bd4ff; font-size: 0.74rem; margin: 0 0 8px; }}
    .badge {{ display: inline-block; padding: 7px 14px; border-radius: 999px; color: #06111c; font-weight: bold; letter-spacing: 0.08em; }}
    .card {{ background: rgba(16, 24, 39, 0.94); border: 1px solid #2d3c5a; border-radius: 14px; padding: 16px; margin-bottom: 16px; box-shadow: 0 18px 44px rgba(0, 0, 0, 0.28); }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(3, minmax(150px, 1fr)); gap: 12px; margin-top: 12px; }}
    .summary-box {{ border: 1px solid #2d3c5a; border-radius: 12px; padding: 12px; background: rgba(8, 17, 31, 0.78); }}
    .summary-box p {{ margin: 0; font-size: 0.86rem; color: #9db0cb; text-transform: uppercase; letter-spacing: 0.08em; }}
    .summary-box h3 {{ margin: 6px 0 0; font-size: 1.3rem; color: #edf4ff; }}
    .meter {{ margin-top: 10px; height: 16px; border-radius: 999px; background: #0a1527; border: 1px solid #263653; overflow: hidden; }}
    .meter-fill {{ height: 100%; background: linear-gradient(90deg, #3dd68c 0%, #f6b73c 55%, #ff5a6b 100%); }}
    .checks-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; }}
    .check-card {{ border: 1px solid #2d3c5a; border-radius: 12px; padding: 12px; background: rgba(8, 17, 31, 0.78); }}
    .check-sub {{ margin: 0 0 8px; color: #9db0cb; font-size: 0.92rem; }}
    .bar-row {{ display: grid; grid-template-columns: 130px 1fr auto; gap: 8px; align-items: center; margin: 6px 0; font-size: 0.88rem; color: #c4d3ea; }}
    .bar {{ height: 10px; border-radius: 999px; background: #0a1527; border: 1px solid #22314d; overflow: hidden; }}
    .bar-fill {{ height: 100%; }}
    .bar-fill.score {{ background: #ff5a6b; }}
    .bar-fill.conf {{ background: #5aa9ff; }}
    .timeline-track {{ position: relative; height: 32px; border-radius: 12px; background: linear-gradient(90deg, rgba(90, 169, 255, 0.08), rgba(90, 169, 255, 0.02)), rgba(7, 14, 24, 0.86); border: 1px solid #2d3c5a; }}
    .timeline-block {{ position: absolute; top: 4px; height: 24px; background: linear-gradient(90deg, rgba(246, 183, 60, 0.88), rgba(255, 90, 107, 0.94)); border-radius: 8px; opacity: 0.85; }}
    .timeline-empty {{ color: #9db0cb; font-style: italic; }}
    h1, h2, h3, strong {{ color: #edf4ff; }}
    p, li {{ color: #c4d3ea; line-height: 1.55; }}
    ul {{ margin-top: 8px; padding-left: 20px; }}
  </style>
</head>
<body>
  <div class="shell">
  <div class="header">
    <p class="eyebrow">Case file / forensic report</p>
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
  </div>
</body>
</html>
"""
