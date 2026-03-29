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


# ── Advanced forensic probes (ffmpeg-based) ──────────────────────────────────


def _run_ffmpeg(args: list[str], timeout: int = 300) -> str:
    """Run an ffmpeg command and return combined stderr (where filter output goes)."""
    command = ["ffmpeg", "-hide_banner"] + args
    process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return process.stderr + process.stdout


def build_scene_detect(path: str, threshold: float = 0.3, timeout: int = 300) -> list[dict[str, Any]]:
    """Run ffmpeg scene-change detection and return a list of scene-change events."""
    output = _run_ffmpeg(
        [
            "-i", path,
            "-vf", f"select='gt(scene,{threshold})',showinfo",
            "-f", "null", "-",
        ],
        timeout=timeout,
    )
    import re
    scenes: list[dict[str, Any]] = []
    for line in output.splitlines():
        # showinfo prints lines like: [Parsed_showinfo...] n: 42 pts: 84084 pts_time:3.503500 ...
        m = re.search(r"pts_time:\s*([\d.]+)", line)
        score_m = re.search(r"score:\s*([\d.]+)", line)
        if m:
            ts = float(m.group(1))
            sc = float(score_m.group(1)) if score_m else threshold
            scenes.append({"pts_time": ts, "score": sc})
    return scenes


def build_qp_probe(path: str, timeout: int = 300) -> list[dict[str, Any]]:
    """Extract per-frame QP (quantization parameter) stats using ffmpeg debug QP output."""
    output = _run_ffmpeg(
        [
            "-i", path,
            "-vf", "showinfo",
            "-f", "null", "-",
        ],
        timeout=timeout,
    )
    import re
    frames: list[dict[str, Any]] = []
    for line in output.splitlines():
        m = re.search(
            r"n:\s*(\d+)\s+.*pts_time:\s*([\d.]+).*iskey:(\d).*type:([IPB])",
            line,
        )
        if m:
            frames.append({
                "n": int(m.group(1)),
                "pts_time": float(m.group(2)),
                "key_frame": int(m.group(3)),
                "pict_type": m.group(4),
            })
    return frames


def extract_audio_pcm(
    path: str, output_path: str, sample_rate: int = 16000, timeout: int = 120
) -> bool:
    """Extract audio as mono 16-bit PCM WAV. Returns True on success."""
    command = [
        "ffmpeg", "-hide_banner", "-y",
        "-i", path,
        "-vn", "-ac", "1", "-ar", str(sample_rate),
        "-sample_fmt", "s16", "-f", "wav",
        output_path,
    ]
    process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return process.returncode == 0


def extract_thumbnail(path: str, output_path: str, timeout: int = 30) -> bool:
    """Extract embedded thumbnail (if any) from video metadata."""
    command = [
        "ffmpeg", "-hide_banner", "-y",
        "-i", path,
        "-an", "-vn",
        "-map", "0:v:1",  # second video stream is often thumbnail
        "-frames:v", "1",
        output_path,
    ]
    process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if process.returncode != 0:
        # Try attached_pic disposition
        command2 = [
            "ffmpeg", "-hide_banner", "-y",
            "-i", path,
            "-map", "0:v", "-disposition:v", "attached_pic",
            "-frames:v", "1",
            output_path,
        ]
        process2 = subprocess.run(
            command2,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return process2.returncode == 0
    return True


def build_bitstream_probe(path: str, max_packets: int = 500, timeout: int = 180) -> list[dict[str, Any]]:
    """Extract detailed per-packet bitstream info including NAL unit types for H.264/H.265."""
    result = _run_ffprobe(
        [
            "-select_streams", "v:0",
            "-show_packets",
            "-show_entries",
            "packet=pts_time,dts_time,size,flags,pos,duration_time,stream_index",
            "-read_intervals", f"%+#" + str(max_packets),
            path,
        ],
        timeout=timeout,
    )
    return result.get("packets", [])


def build_detailed_frame_probe(path: str, timeout: int = 300) -> dict[str, Any]:
    """Extended frame probe including repeat_pict, interlaced, and side data info."""
    return _run_ffprobe(
        [
            "-select_streams", "v:0",
            "-show_frames",
            "-show_entries",
            (
                "frame=best_effort_timestamp_time,pkt_duration_time,key_frame,pict_type,"
                "coded_picture_number,pkt_size,width,height,interlaced_frame,top_field_first,"
                "color_range,color_space,color_transfer,color_primaries,repeat_pict,"
                "chroma_location,sample_aspect_ratio"
            ),
            path,
        ],
        timeout=timeout,
    )
