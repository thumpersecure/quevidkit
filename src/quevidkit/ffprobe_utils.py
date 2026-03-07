from __future__ import annotations

import json
import shlex
import subprocess
from typing import Any


class FFProbeError(RuntimeError):
    """Raised when ffprobe fails or returns invalid JSON."""


def _run_ffprobe(args: list[str], timeout: int = 120) -> dict[str, Any]:
    command = ["ffprobe", "-v", "error", "-hide_banner", "-print_format", "json"] + args
    process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if process.returncode != 0:
        raise FFProbeError(
            f"ffprobe failed ({process.returncode}): {process.stderr.strip()[:500]}"
        )
    try:
        return json.loads(process.stdout or "{}")
    except json.JSONDecodeError as exc:
        snippet = (process.stdout or "")[:400]
        raise FFProbeError(f"ffprobe returned invalid JSON: {snippet}") from exc


def build_basic_probe(path: str) -> dict[str, Any]:
    return _run_ffprobe(
        [
            "-show_format",
            "-show_streams",
            "-show_chapters",
            "-show_entries",
            (
                "format=filename,format_name,format_long_name,start_time,duration,size,bit_rate,"
                "probe_score,tags:stream=index,codec_type,codec_name,codec_long_name,codec_tag_string,"
                "profile,level,pix_fmt,width,height,sample_aspect_ratio,display_aspect_ratio,r_frame_rate,"
                "avg_frame_rate,time_base,start_time,duration,bit_rate,nb_frames,has_b_frames,"
                "extradata_size,color_range,color_space,color_transfer,color_primaries,field_order,tags,"
                "disposition"
            ),
            path,
        ]
    )


def build_packet_probe(path: str, timeout: int = 180) -> dict[str, Any]:
    return _run_ffprobe(
        [
            "-select_streams",
            "v:0",
            "-show_packets",
            "-show_entries",
            "packet=stream_index,pts_time,dts_time,duration_time,size,pos,flags",
            path,
        ],
        timeout=timeout,
    )


def build_frame_probe(path: str, timeout: int = 180) -> dict[str, Any]:
    return _run_ffprobe(
        [
            "-select_streams",
            "v:0",
            "-show_frames",
            "-show_entries",
            (
                "frame=best_effort_timestamp_time,pkt_duration_time,key_frame,pict_type,coded_picture_number,"
                "pkt_size,width,height,interlaced_frame,top_field_first,color_range,color_space,"
                "color_transfer,color_primaries"
            ),
            path,
        ],
        timeout=timeout,
    )


def parse_ratio(value: str | None) -> float | None:
    if not value or value in {"N/A", "0/0"}:
        return None
    if "/" not in value:
        try:
            return float(value)
        except ValueError:
            return None
    numerator, denominator = value.split("/", maxsplit=1)
    try:
        n = float(numerator)
        d = float(denominator)
    except ValueError:
        return None
    if d == 0:
        return None
    return n / d


def to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def pretty_command(args: list[str]) -> str:
    return shlex.join(args)
