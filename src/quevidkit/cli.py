from __future__ import annotations

import argparse
import json
import os
import sys

from .models import AnalysisOptions
from .pipeline import analyze_video
from .reporting import result_to_html


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qvk",
        description="quevidkit forensic video tampering analyzer",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Analyze a single video file")
    analyze.add_argument("video_path", help="Path to video file")
    analyze.add_argument("--preset", choices=["fast", "balanced", "deep"], default="balanced")
    analyze.add_argument("--sample-fps", type=float, default=2.0)
    analyze.add_argument("--max-frames", type=int, default=2000)
    analyze.add_argument("--sensitivity", type=float, default=0.7)
    analyze.add_argument("--no-metadata-scan", action="store_true")
    analyze.add_argument("--no-packet-scan", action="store_true")
    analyze.add_argument("--no-frame-scan", action="store_true")
    analyze.add_argument("--no-quality-scan", action="store_true")
    analyze.add_argument("--debug", action="store_true", help="Include raw probe payloads")
    analyze.add_argument("--json-out", help="Path to save JSON report")
    analyze.add_argument("--html-out", help="Path to save HTML report")

    serve = subparsers.add_parser("serve", help="Run web app backend")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=8000)
    return parser


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
    payload = result.to_dict()
    print(json.dumps(payload, indent=2))

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
