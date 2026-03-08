from __future__ import annotations

import argparse
import json
import os
import sys

from .models import AnalysisOptions, AnalysisResult
from .pipeline import analyze_video
from .reporting import result_to_html


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qvk",
        description="quevidkit forensic video tampering analyzer",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser(
        "analyze",
        help="Analyze a video file for tampering and manipulation.",
    )
    analyze.add_argument("video_path", help="Path to the video file to analyze.")
    analyze.add_argument(
        "--preset",
        choices=["fast", "balanced", "deep"],
        default="balanced",
        help="Analysis preset: fast (quick scan), balanced (recommended), thorough (deep analysis).",
    )
    analyze.add_argument("--sample-fps", type=float, default=2.0, help="Frames per second to sample for quality analysis.")
    analyze.add_argument("--max-frames", type=int, default=2000, help="Maximum number of frames to sample.")
    analyze.add_argument(
        "--sensitivity",
        type=float,
        default=0.7,
        help=(
            "Detection sensitivity (0.05-0.99). Higher values detect more potential tampering "
            "but may have more false positives. Default: 0.7."
        ),
    )
    analyze.add_argument("--no-metadata-scan", action="store_true", help="Disable container/metadata checks.")
    analyze.add_argument("--no-packet-scan", action="store_true", help="Disable packet timing checks.")
    analyze.add_argument("--no-frame-scan", action="store_true", help="Disable frame structure checks.")
    analyze.add_argument("--no-quality-scan", action="store_true", help="Disable OpenCV frame quality checks.")
    analyze.add_argument("--debug", action="store_true", help="Include raw probe payloads in JSON output.")
    analyze.add_argument("--json-out", help="Save the full JSON analysis report to this file.")
    analyze.add_argument(
        "--html-out",
        help="Save a self-contained HTML forensic report to this file.",
    )

    serve = subparsers.add_parser(
        "serve",
        help="Start the web server for browser-based analysis.",
    )
    serve.add_argument("--host", default="0.0.0.0", help="Host address to bind the server to.")
    serve.add_argument("--port", type=int, default=8000, help="Port to listen on.")
    return parser


_VERDICT_LABELS = {
    "tampered": ("[WARNING]", "Forensic signals indicate likely video manipulation."),
    "suspicious": ("[CAUTION]", "Anomalies detected; manual review is recommended."),
    "authentic": ("[OK]", "No significant tampering indicators detected."),
    "inconclusive": ("[?]", "Evidence quality insufficient for a definitive verdict."),
}

_SEP = "=" * 60


def _print_summary(result: AnalysisResult) -> None:
    payload = result.to_dict()
    prefix, description = _VERDICT_LABELS.get(result.label, ("[?]", "Unknown verdict."))
    prob_pct = f"{result.tamper_probability * 100:.1f}%"
    conf_pct = f"{result.confidence * 100:.1f}%"
    size_mb = result.file_size_bytes / (1024 * 1024)

    print(_SEP)
    print(f"  File    : {result.video_path}")
    print(f"  Duration: {payload['video_duration_s']}s  |  Size: {size_mb:.1f} MB")
    print(f"  SHA-256 : {result.file_sha256[:16]}...")
    print(_SEP)
    print(f"  {prefix} {result.label.upper()}")
    print(f"  {description}")
    print(f"  Tamper probability : {prob_pct}")
    print(f"  Confidence         : {conf_pct}")
    print(_SEP)
    if result.checks:
        print("  Check results:")
        for check in result.checks:
            print(f"    {check.name:<32}  score={check.score:.2f}  conf={check.confidence:.2f}  [{check.category}]")
        print(_SEP)
    if result.explanation:
        print("  Explanation:")
        for line in result.explanation:
            print(f"    - {line}")
        print(_SEP)


def _command_analyze(args: argparse.Namespace) -> int:
    if not os.path.exists(args.video_path):
        print(f"File not found: {args.video_path}", file=sys.stderr)
        return 2

    options = AnalysisOptions.from_dict(
        {
            "preset": args.preset,
            "sample_fps": args.sample_fps,
            "max_frames": args.max_frames,
            "sensitivity": args.sensitivity,
            "enable_metadata_scan": not args.no_metadata_scan,
            "enable_packet_scan": not args.no_packet_scan,
            "enable_frame_scan": not args.no_frame_scan,
            "enable_quality_scan": not args.no_quality_scan,
            "include_debug_payload": args.debug,
        }
    )
    result = analyze_video(args.video_path, options=options)
    _print_summary(result)

    payload = result.to_dict()
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
    if args.html_out:
        with open(args.html_out, "w", encoding="utf-8") as handle:
            handle.write(result_to_html(result))
    return 0


def _command_serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run("quevidkit.webapp:app", host=args.host, port=args.port, reload=False)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "analyze":
        return _command_analyze(args)
    if args.command == "serve":
        return _command_serve(args)
    parser.error(f"Unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
