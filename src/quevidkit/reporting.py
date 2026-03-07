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


def result_to_html(result: AnalysisResult) -> str:
    rows = []
    for check in result.checks:
        rows.append(
            "<tr>"
            f"<td>{html.escape(check.name)}</td>"
            f"<td>{html.escape(check.category)}</td>"
            f"<td>{check.score:.3f}</td>"
            f"<td>{check.confidence:.3f}</td>"
            f"<td>{html.escape(check.summary)}</td>"
            "</tr>"
        )
    segments_html = "".join(
        (
            "<li>"
            f"[{segment.category}] {segment.start_s:.2f}s - {segment.end_s:.2f}s "
            f"(confidence {segment.confidence:.2f})"
            "</li>"
        )
        for segment in result.suspicious_segments[:20]
    )
    explanation = "".join(f"<li>{html.escape(line)}</li>" for line in result.explanation)
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>quevidkit forensic report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #111; background: #fafafa; }}
    .badge {{ display: inline-block; padding: 6px 12px; border-radius: 16px; color: white; font-weight: bold; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
    th {{ background: #f0f0f0; }}
    .card {{ background: white; border: 1px solid #e2e2e2; border-radius: 8px; padding: 16px; margin-bottom: 16px; }}
  </style>
</head>
<body>
  <h1>quevidkit forensic report</h1>
  <div class="card">
    <div class="badge" style="background:{decision_color(result.label)}">{html.escape(result.label.upper())}</div>
    <p><strong>Tamper probability:</strong> {result.tamper_probability:.3f}</p>
    <p><strong>Confidence:</strong> {result.confidence:.3f}</p>
    <p><strong>Video:</strong> {html.escape(result.video_path)}</p>
    <p><strong>SHA256:</strong> {html.escape(result.file_sha256)}</p>
    <p><strong>Duration:</strong> {result.duration_s:.2f}s</p>
  </div>
  <div class="card">
    <h2>Explanation</h2>
    <ul>{explanation}</ul>
  </div>
  <div class="card">
    <h2>Checks</h2>
    <table>
      <thead><tr><th>Name</th><th>Category</th><th>Score</th><th>Confidence</th><th>Summary</th></tr></thead>
      <tbody>
        {''.join(rows)}
      </tbody>
    </table>
  </div>
  <div class="card">
    <h2>Top suspicious segments</h2>
    <ul>{segments_html or '<li>None</li>'}</ul>
  </div>
</body>
</html>
"""
