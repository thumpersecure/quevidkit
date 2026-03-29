from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict
from statistics import median
from typing import Any

from .ffprobe_utils import (
    FFProbeError,
    build_basic_probe,
    build_bitstream_probe,
    build_detailed_frame_probe,
    build_frame_probe,
    build_packet_probe,
    build_qp_probe,
    build_scene_detect,
    extract_audio_pcm,
    extract_thumbnail,
    parse_ratio,
    to_float,
)
from .models import (
    AnalysisOptions,
    AnalysisResult,
    CheckResult,
    SegmentEvidence,
    file_size,
    now_utc_iso,
    sha256_for_file,
)
from .scoring import clamp01, fuse_scores


def _mad(values: list[float], fallback: float = 1.0) -> float:
    if not values:
        return fallback
    med = median(values)
    spread = median([abs(v - med) for v in values])
    return spread if spread > 1e-9 else fallback


def _z(value: float, values: list[float]) -> float:
    med = median(values) if values else 0.0
    mad = _mad(values, fallback=1.0)
    return (value - med) / (1.4826 * mad + 1e-9)


def _median_and_mad(values: list[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 1.0
    med = median(values)
    mad = _mad(values, fallback=1.0)
    return med, mad


def _extract_video_stream(basic_probe: dict[str, Any]) -> dict[str, Any] | None:
    streams = basic_probe.get("streams", [])
    for stream in streams:
        if stream.get("codec_type") == "video":
            return stream
    return None


def _extract_audio_stream(basic_probe: dict[str, Any]) -> dict[str, Any] | None:
    streams = basic_probe.get("streams", [])
    for stream in streams:
        if stream.get("codec_type") == "audio":
            return stream
    return None


def _extract_duration(basic_probe: dict[str, Any], video_stream: dict[str, Any] | None) -> float:
    duration = to_float(basic_probe.get("format", {}).get("duration"))
    if duration is None and video_stream:
        duration = to_float(video_stream.get("duration"))
    return float(duration or 0.0)


def _extract_fps(video_stream: dict[str, Any] | None) -> float:
    if not video_stream:
        return 0.0
    return float(
        parse_ratio(video_stream.get("avg_frame_rate"))
        or parse_ratio(video_stream.get("r_frame_rate"))
        or 0.0
    )


def metadata_codec_checks(basic_probe: dict[str, Any]) -> CheckResult:
    format_data = basic_probe.get("format", {})
    video = _extract_video_stream(basic_probe)
    audio = _extract_audio_stream(basic_probe)

    findings: list[tuple[str, float]] = []
    details: dict[str, Any] = {}

    format_duration = to_float(format_data.get("duration"))
    video_duration = to_float(video.get("duration")) if video else None
    if format_duration and video_duration and format_duration > 0:
        duration_rel_diff = abs(format_duration - video_duration) / max(format_duration, 1e-9)
        details["duration_relative_diff"] = duration_rel_diff
        if duration_rel_diff > 0.02 and abs(format_duration - video_duration) > 0.5:
            severity = clamp01((duration_rel_diff - 0.02) / 0.12)
            findings.append(("container/stream duration mismatch", severity))

    declared_bitrate = to_float(format_data.get("bit_rate"))
    size_bytes = to_float(format_data.get("size"))
    if declared_bitrate and size_bytes and format_duration and format_duration > 0:
        observed = (size_bytes * 8.0) / format_duration
        rel_diff = abs(observed - declared_bitrate) / max(declared_bitrate, 1.0)
        details["bitrate_relative_diff"] = rel_diff
        details["observed_bitrate"] = observed
        if rel_diff > 0.25:
            findings.append(("declared bitrate mismatch", clamp01((rel_diff - 0.25) / 0.5)))

    if audio:
        audio_duration = to_float(audio.get("duration"))
        if audio_duration and format_duration:
            av_diff = abs(audio_duration - format_duration)
            details["audio_video_duration_diff_s"] = av_diff
            if av_diff > 0.35:
                findings.append(("audio/video duration mismatch", clamp01((av_diff - 0.35) / 3.0)))

    tag_values = []
    for tag_source in (format_data.get("tags", {}), (video or {}).get("tags", {})):
        if isinstance(tag_source, dict):
            for key in ("encoder", "software", "comment"):
                value = tag_source.get(key)
                if value:
                    tag_values.append(str(value))

    editor_markers = (
        "adobe",
        "premiere",
        "davinci",
        "capcut",
        "final cut",
        "imovie",
        "handbrake",
        "lavf",
    )
    if any(marker in " ".join(tag_values).lower() for marker in editor_markers):
        findings.append(("editing/transcoding software marker present", 0.2))

    if video:
        details["video_codec"] = video.get("codec_name")
        details["pixel_format"] = video.get("pix_fmt")
        details["resolution"] = f"{video.get('width')}x{video.get('height')}"
    details["format"] = format_data.get("format_name")

    if not findings:
        summary = "Metadata and container checks look consistent."
        score = 0.05
    else:
        weighted = sum(weight for _, weight in findings) / len(findings)
        score = clamp01(weighted)
        summary = "; ".join(item for item, _ in findings)

    confidence = 0.85 if video else 0.45
    if not format_duration:
        confidence -= 0.15
    if not declared_bitrate:
        confidence -= 0.1
    return CheckResult(
        name="metadata_codec_consistency",
        category="metadata",
        score=score,
        confidence=clamp01(confidence),
        summary=summary,
        details={**details, "findings": findings},
    )


def packet_timing_checks(packet_probe: dict[str, Any], fps_hint: float) -> CheckResult:
    packets = packet_probe.get("packets", [])
    if not packets:
        return CheckResult(
            name="packet_timing_anomalies",
            category="timing",
            score=0.0,
            confidence=0.05,
            summary="Packet-level probe unavailable.",
            details={},
        )

    dts = [to_float(packet.get("dts_time")) for packet in packets]
    pts = [to_float(packet.get("pts_time")) for packet in packets]
    dts = [value for value in dts if value is not None]
    pts = [value for value in pts if value is not None]

    non_monotonic = 0
    monotonic_segments: list[SegmentEvidence] = []
    for index in range(1, len(dts)):
        if dts[index] <= dts[index - 1] - 1e-6:
            non_monotonic += 1
            start = dts[index - 1]
            end = dts[index]
            monotonic_segments.append(
                SegmentEvidence(
                    category="timing_break",
                    start_s=max(0.0, min(start, end)),
                    end_s=max(start, end),
                    confidence=0.9,
                    details={"reason": "non-monotonic dts"},
                )
            )

    timing_series = dts if len(dts) >= 3 else pts
    positive_deltas = []
    for index in range(1, len(timing_series)):
        delta = timing_series[index] - timing_series[index - 1]
        if delta > 0:
            positive_deltas.append(delta)
    med_delta = median(positive_deltas) if positive_deltas else (1.0 / fps_hint if fps_hint > 0 else 0.033)
    spikes = []
    for index in range(1, len(timing_series)):
        delta = timing_series[index] - timing_series[index - 1]
        if delta <= 0:
            continue
        if delta > med_delta * 3.5 or delta < med_delta * 0.25:
            spikes.append((index, delta))

    spike_segments = [
        SegmentEvidence(
            category="timestamp_spike",
            start_s=max(0.0, timing_series[idx - 1]),
            end_s=max(timing_series[idx - 1], timing_series[idx]),
            confidence=0.75,
            details={"delta": delta, "median_delta": med_delta},
        )
        for idx, delta in spikes
        if idx < len(timing_series)
    ]

    non_monotonic_rate = non_monotonic / max(1, len(dts))
    spike_rate = len(spikes) / max(1, len(timing_series))
    score = clamp01(max((non_monotonic_rate - 0.001) / 0.01, (spike_rate - 0.005) / 0.05, 0.0))
    summary = (
        "No significant packet timing anomalies."
        if score < 0.1
        else "Packet timing anomalies detected (DTS/PTS discontinuities)."
    )
    confidence = clamp01(0.55 + min(len(packets), 10000) / 15000.0)
    return CheckResult(
        name="packet_timing_anomalies",
        category="timing",
        score=score,
        confidence=confidence,
        summary=summary,
        details={
            "packet_count": len(packets),
            "non_monotonic_dts_count": non_monotonic,
            "non_monotonic_rate": non_monotonic_rate,
            "pts_spike_count": len(spikes),
            "pts_spike_rate": spike_rate,
        },
        segments=(monotonic_segments + spike_segments)[:150],
    )


def frame_structure_checks(frame_probe: dict[str, Any]) -> CheckResult:
    frames = frame_probe.get("frames", [])
    if not frames:
        return CheckResult(
            name="frame_structure_anomalies",
            category="codec",
            score=0.0,
            confidence=0.05,
            summary="Frame-level ffprobe data unavailable.",
            details={},
        )

    keyframe_indices = [idx for idx, frame in enumerate(frames) if int(frame.get("key_frame") or 0) == 1]
    key_intervals = []
    for idx in range(1, len(keyframe_indices)):
        key_intervals.append(keyframe_indices[idx] - keyframe_indices[idx - 1])
    gop_cv = 0.0
    if key_intervals:
        avg = sum(key_intervals) / len(key_intervals)
        variance = sum((x - avg) ** 2 for x in key_intervals) / max(1, len(key_intervals) - 1)
        std = variance**0.5
        gop_cv = std / max(avg, 1e-9)

    resolutions = defaultdict(int)
    color_profiles = set()
    switch_segments: list[SegmentEvidence] = []
    for frame in frames:
        width = frame.get("width")
        height = frame.get("height")
        ts = to_float(frame.get("best_effort_timestamp_time")) or 0.0
        if width and height:
            resolutions[(int(width), int(height))] += 1
        profile = (
            frame.get("color_space"),
            frame.get("color_transfer"),
            frame.get("color_primaries"),
        )
        if any(profile):
            color_profiles.add(profile)
        if len(resolutions) > 1:
            switch_segments.append(
                SegmentEvidence(
                    category="resolution_switch",
                    start_s=max(0.0, ts - 0.2),
                    end_s=ts + 0.2,
                    confidence=0.8,
                    details={"resolutions_seen": list(resolutions.keys())},
                )
            )

    gop_score = clamp01((gop_cv - 0.6) / 0.9)
    resolution_switch_score = 0.75 if len(resolutions) > 1 else 0.0
    color_switch_score = clamp01((len(color_profiles) - 1) / 2.0) if len(color_profiles) > 1 else 0.0
    score = clamp01((gop_score * 0.45) + (resolution_switch_score * 0.35) + (color_switch_score * 0.2))

    if score < 0.1:
        summary = "Frame structure looks stable."
    else:
        summary = "Frame-level codec structure anomalies detected."

    return CheckResult(
        name="frame_structure_anomalies",
        category="codec",
        score=score,
        confidence=clamp01(0.5 + min(len(frames), 6000) / 10000.0),
        summary=summary,
        details={
            "frame_count": len(frames),
            "gop_interval_cv": gop_cv,
            "unique_resolutions": [f"{w}x{h}" for (w, h) in resolutions.keys()],
            "color_profile_variants": len(color_profiles),
        },
        segments=switch_segments[:120],
    )


def _frame_hash(gray_frame: Any) -> int:
    import numpy as np

    resized = gray_frame
    if resized.shape[1] < 9 or resized.shape[0] < 8:
        raise ValueError("frame too small for hash")
    diff = resized[:, 1:9] > resized[:, :8]
    bits = np.packbits(diff.astype("uint8"), axis=None)
    value = 0
    for byte in bits:
        value = (value << 8) | int(byte)
    return value


def _hamming(a: int, b: int) -> int:
    return (a ^ b).bit_count()


def _compute_blockiness(gray_frame: Any) -> float:
    import numpy as np

    gray = gray_frame.astype("float32")
    if gray.shape[0] < 17 or gray.shape[1] < 17:
        return 0.0
    v_edges = np.abs(gray[:, 7::8] - gray[:, 8::8]).mean() if gray.shape[1] > 8 else 0.0
    h_edges = np.abs(gray[7::8, :] - gray[8::8, :]).mean() if gray.shape[0] > 8 else 0.0
    inner_v = np.abs(gray[:, 3::8] - gray[:, 4::8]).mean() if gray.shape[1] > 8 else 0.0
    inner_h = np.abs(gray[3::8, :] - gray[4::8, :]).mean() if gray.shape[0] > 8 else 0.0
    return float(max(0.0, (v_edges + h_edges) - (inner_v + inner_h)))


def opencv_frame_quality_checks(
    video_path: str, duration_s: float, fps_hint: float, options: AnalysisOptions
) -> CheckResult:
    try:
        import cv2  # type: ignore
        import numpy as np
    except ImportError:
        return CheckResult(
            name="frame_quality_shift",
            category="quality",
            score=0.0,
            confidence=0.01,
            summary="OpenCV is not installed; frame analysis skipped.",
            details={"reason": "opencv-python dependency missing"},
        )

    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        return CheckResult(
            name="frame_quality_shift",
            category="quality",
            score=0.0,
            confidence=0.05,
            summary="Video decoding failed for frame analysis.",
            details={},
        )

    native_fps = cap.get(cv2.CAP_PROP_FPS) or fps_hint or 30.0
    sample_stride = max(1, int(round(native_fps / max(options.sample_fps, 0.2))))

    sampled_timestamps: list[float] = []
    hash_distances: list[float] = []
    pixel_diffs: list[float] = []
    blur_values: list[float] = []
    blockiness_values: list[float] = []
    delta_ts: list[float] = []

    duplicate_runs: list[tuple[int, int]] = []
    missing_segments: list[SegmentEvidence] = []
    quality_segments: list[SegmentEvidence] = []

    prev_gray = None
    prev_hash = None
    prev_ts = None
    run_start = None

    frame_index = -1
    sampled_count = 0

    while sampled_count < options.max_frames:
        ok = cap.grab()
        if not ok:
            break
        frame_index += 1
        if frame_index % sample_stride != 0:
            continue
        ok, frame = cap.retrieve()
        if not ok or frame is None:
            continue

        ts_msec = cap.get(cv2.CAP_PROP_POS_MSEC)
        timestamp = (ts_msec / 1000.0) if ts_msec > 0 else (frame_index / native_fps)
        if duration_s > 0:
            timestamp = min(timestamp, duration_s)

        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        gray = cv2.resize(gray, (320, 180), interpolation=cv2.INTER_AREA)

        blur = float(cv2.Laplacian(gray, cv2.CV_64F).var())
        blockiness = _compute_blockiness(gray)

        if prev_gray is not None:
            diff = float(np.mean(np.abs(gray.astype("float32") - prev_gray.astype("float32"))) / 255.0)
            pixel_diffs.append(diff)
            try:
                h = _frame_hash(gray[:8, :9])
                if prev_hash is not None:
                    hamming = _hamming(prev_hash, h) / 64.0
                    hash_distances.append(hamming)
                    if hamming < 0.06 and diff < 0.01:
                        if run_start is None:
                            run_start = sampled_count - 1
                    else:
                        if run_start is not None and (sampled_count - run_start) >= 3:
                            duplicate_runs.append((run_start, sampled_count - 1))
                        run_start = None
                prev_hash = h
            except ValueError:
                pass

            if prev_ts is not None:
                dt = max(1e-6, timestamp - prev_ts)
                delta_ts.append(dt)

        sampled_timestamps.append(timestamp)
        blur_values.append(blur)
        blockiness_values.append(blockiness)
        prev_gray = gray
        prev_ts = timestamp
        sampled_count += 1

    cap.release()

    if run_start is not None and sampled_count - run_start >= 3:
        duplicate_runs.append((run_start, sampled_count - 1))

    expected_step = sample_stride / max(native_fps, 1e-6)
    for index, delta in enumerate(delta_ts, start=1):
        if delta > expected_step * 1.7:
            missed = int(round(delta / expected_step)) - 1
            start = sampled_timestamps[index - 1]
            end = sampled_timestamps[index]
            missing_segments.append(
                SegmentEvidence(
                    category="missing_frames",
                    start_s=start,
                    end_s=end,
                    confidence=clamp01(0.55 + missed * 0.08),
                    details={"estimated_missing_frames": max(1, missed), "delta_s": delta},
                )
            )

    blur_deltas = [abs(blur_values[i] - blur_values[i - 1]) for i in range(1, len(blur_values))]
    block_deltas = [abs(blockiness_values[i] - blockiness_values[i - 1]) for i in range(1, len(blockiness_values))]
    combined_shifts = []
    for i in range(min(len(blur_deltas), len(block_deltas))):
        combined_shifts.append((blur_deltas[i] * 0.7) + (block_deltas[i] * 0.3))
    if combined_shifts:
        med_shift, mad_shift = _median_and_mad(combined_shifts)
        for idx, shift in enumerate(combined_shifts, start=1):
            z_score = (shift - med_shift) / (1.4826 * mad_shift + 1e-9)
            if z_score > 4.0:
                quality_segments.append(
                    SegmentEvidence(
                        category="quality_shift",
                        start_s=max(0.0, sampled_timestamps[idx - 1]),
                        end_s=sampled_timestamps[idx],
                        confidence=clamp01(min(0.98, 0.55 + (z_score / 10.0))),
                        details={"z_score": z_score, "shift_value": shift},
                    )
                )

    dup_rate = len(duplicate_runs) / max(1, sampled_count)
    missing_rate = len(missing_segments) / max(1, sampled_count)
    quality_rate = len(quality_segments) / max(1, sampled_count)
    score = clamp01((dup_rate * 8.0) + (missing_rate * 6.0) + (quality_rate * 10.0))

    all_segments: list[SegmentEvidence] = []
    for run_start_idx, run_end_idx in duplicate_runs:
        all_segments.append(
            SegmentEvidence(
                category="duplicate_frames",
                start_s=sampled_timestamps[run_start_idx],
                end_s=sampled_timestamps[run_end_idx],
                confidence=0.9,
                details={"sampled_run_length": (run_end_idx - run_start_idx + 1)},
            )
        )
    all_segments.extend(missing_segments)
    all_segments.extend(quality_segments)
    all_segments.sort(key=lambda item: item.start_s)

    if score < 0.1:
        summary = "No strong frame-level quality anomalies found."
    else:
        summary = "Frame anomalies indicate possible duplicate/drop or quality discontinuities."

    confidence = clamp01(0.35 + min(sampled_count, options.max_frames) / max(options.max_frames, 1))
    return CheckResult(
        name="frame_quality_shift",
        category="quality",
        score=score,
        confidence=confidence,
        summary=summary,
        details={
            "sampled_frames": sampled_count,
            "sample_stride": sample_stride,
            "duplicate_runs": len(duplicate_runs),
            "estimated_missing_events": len(missing_segments),
            "quality_shift_events": len(quality_segments),
            "duplicate_event_rate": dup_rate,
            "missing_event_rate": missing_rate,
            "quality_shift_rate": quality_rate,
        },
        segments=all_segments[:200],
    )


# ── Advanced forensic checks (deep mode) ─────────────────────────────────────


def compression_consistency_checks(
    frame_probe: dict[str, Any], packet_probe: dict[str, Any], duration_s: float
) -> CheckResult:
    """Detect re-compression by analyzing packet-size distributions across temporal segments.

    In a singly-compressed video, the distribution of packet sizes for each frame type
    (I/P/B) should be roughly stationary. Re-encoding a portion shifts that distribution
    in the affected segment.
    """
    frames = frame_probe.get("frames", [])
    packets = packet_probe.get("packets", [])
    if len(frames) < 30 and len(packets) < 30:
        return CheckResult(
            name="compression_consistency",
            category="codec",
            score=0.0,
            confidence=0.05,
            summary="Insufficient data for compression consistency analysis.",
            details={},
        )

    # Build per-frame-type size series with timestamps
    type_sizes: dict[str, list[tuple[float, int]]] = {"I": [], "P": [], "B": []}
    for frame in frames:
        ts = to_float(frame.get("best_effort_timestamp_time")) or 0.0
        size = to_float(frame.get("pkt_size")) or 0
        ptype = (frame.get("pict_type") or "P")[0].upper()
        if ptype in type_sizes:
            type_sizes[ptype].append((ts, int(size)))

    # If frame data is sparse, fall back to packets
    if sum(len(v) for v in type_sizes.values()) < 20:
        for pkt in packets:
            ts = to_float(pkt.get("pts_time") or pkt.get("dts_time")) or 0.0
            size = to_float(pkt.get("size")) or 0
            flags = str(pkt.get("flags", ""))
            ptype = "I" if "K" in flags else "P"
            type_sizes[ptype].append((ts, int(size)))

    # Split timeline into windows and compare distributions
    n_windows = 6
    window_dur = max(duration_s / n_windows, 1.0) if duration_s > 0 else 10.0

    findings: list[tuple[str, float]] = []
    segments: list[SegmentEvidence] = []
    details: dict[str, Any] = {"windows": n_windows}

    for ftype, series in type_sizes.items():
        if len(series) < 10:
            continue
        # Bin into windows
        windows: list[list[int]] = [[] for _ in range(n_windows)]
        for ts, size in series:
            idx = min(int(ts / window_dur), n_windows - 1) if window_dur > 0 else 0
            if 0 <= idx < n_windows:
                windows[idx].append(size)

        # Compute per-window median size
        window_medians = []
        for w in windows:
            if len(w) >= 3:
                window_medians.append(median(w))
        if len(window_medians) < 3:
            continue

        global_med = median([s for _, s in series])
        # Detect windows with significantly different median (>40% shift)
        for widx, w in enumerate(windows):
            if len(w) < 3:
                continue
            w_med = median(w)
            if global_med > 0:
                rel_shift = abs(w_med - global_med) / global_med
                if rel_shift > 0.40:
                    severity = clamp01((rel_shift - 0.40) / 0.6)
                    start_s = widx * window_dur
                    end_s = min((widx + 1) * window_dur, duration_s)
                    findings.append((f"{ftype}-frame size shift in window {widx}", severity))
                    segments.append(SegmentEvidence(
                        category="compression_shift",
                        start_s=start_s,
                        end_s=end_s,
                        confidence=clamp01(0.6 + severity * 0.3),
                        details={"frame_type": ftype, "window_median": w_med, "global_median": global_med},
                    ))

        # Also check coefficient of variation across windows
        if window_medians:
            avg_med = sum(window_medians) / len(window_medians)
            if avg_med > 0:
                cv = (sum((m - avg_med) ** 2 for m in window_medians) / len(window_medians)) ** 0.5 / avg_med
                details[f"{ftype}_frame_size_cv"] = round(cv, 4)
                if cv > 0.35:
                    findings.append((f"{ftype}-frame size distribution inconsistency (cv={cv:.2f})", clamp01((cv - 0.35) / 0.5)))

    if not findings:
        score = 0.05
        summary = "Compression characteristics are consistent across the video."
    else:
        score = clamp01(sum(w for _, w in findings) / len(findings))
        summary = "; ".join(f for f, _ in findings[:3])

    data_points = sum(len(v) for v in type_sizes.values())
    confidence = clamp01(0.5 + min(data_points, 5000) / 10000.0)
    return CheckResult(
        name="compression_consistency",
        category="codec",
        score=score,
        confidence=confidence,
        summary=summary,
        details=details,
        segments=segments[:100],
    )


def scene_cut_forensics_checks(
    video_path: str,
    basic_probe: dict[str, Any],
    frame_probe: dict[str, Any],
    fps_hint: float,
    duration_s: float,
) -> CheckResult:
    """Correlate scene changes with GOP structure to detect unnatural edit points.

    Legitimate scene changes usually align with keyframes / GOP boundaries.
    Spliced content often shows scene changes that don't align with the natural GOP cadence,
    or shows suspicious clustering of scene changes.
    """
    try:
        scenes = build_scene_detect(video_path, threshold=0.25, timeout=300)
    except Exception:
        return CheckResult(
            name="scene_cut_forensics",
            category="timing",
            score=0.0,
            confidence=0.05,
            summary="Scene detection failed.",
            details={},
        )

    frames = frame_probe.get("frames", [])
    keyframe_times = []
    for frame in frames:
        if int(frame.get("key_frame") or 0) == 1:
            ts = to_float(frame.get("best_effort_timestamp_time"))
            if ts is not None:
                keyframe_times.append(ts)
    keyframe_times.sort()

    if not scenes:
        return CheckResult(
            name="scene_cut_forensics",
            category="timing",
            score=0.05,
            confidence=0.6,
            summary="No scene changes detected — single continuous shot.",
            details={"scene_count": 0, "keyframe_count": len(keyframe_times)},
        )

    # Compute GOP interval (median distance between keyframes)
    gop_intervals = [keyframe_times[i] - keyframe_times[i - 1] for i in range(1, len(keyframe_times))]
    gop_interval = median(gop_intervals) if gop_intervals else (1.0 / max(fps_hint, 1.0) * 30)

    # Check alignment: for each scene change, find nearest keyframe
    misaligned = 0
    misaligned_segments: list[SegmentEvidence] = []
    alignment_tolerance = gop_interval * 0.15 + (1.0 / max(fps_hint, 1.0))  # within 15% of GOP + 1 frame

    for scene in scenes:
        st = scene["pts_time"]
        # Binary search for nearest keyframe
        nearest_dist = float("inf")
        for kt in keyframe_times:
            d = abs(kt - st)
            if d < nearest_dist:
                nearest_dist = d
            elif d > nearest_dist:
                break  # times are sorted, distance increasing
        if nearest_dist > alignment_tolerance:
            misaligned += 1
            misaligned_segments.append(SegmentEvidence(
                category="misaligned_scene_cut",
                start_s=max(0, st - 0.5),
                end_s=st + 0.5,
                confidence=clamp01(0.6 + (nearest_dist / gop_interval) * 0.2),
                details={"scene_time": st, "nearest_keyframe_dist": nearest_dist},
            ))

    # Check for suspicious clustering of scene changes
    scene_times = [s["pts_time"] for s in scenes]
    cluster_segments: list[SegmentEvidence] = []
    if len(scene_times) >= 3 and duration_s > 0:
        scene_gaps = [scene_times[i] - scene_times[i - 1] for i in range(1, len(scene_times))]
        med_gap = median(scene_gaps) if scene_gaps else duration_s
        for i, gap in enumerate(scene_gaps):
            if med_gap > 0 and gap < med_gap * 0.15 and gap < 0.5:
                cluster_segments.append(SegmentEvidence(
                    category="scene_cluster",
                    start_s=scene_times[i],
                    end_s=scene_times[i + 1],
                    confidence=0.65,
                    details={"gap_s": gap, "median_gap_s": med_gap},
                ))

    misalign_rate = misaligned / max(len(scenes), 1)
    cluster_rate = len(cluster_segments) / max(len(scenes), 1)
    score = clamp01(misalign_rate * 0.7 + cluster_rate * 0.3)

    if score < 0.1:
        summary = "Scene changes align naturally with GOP structure."
    else:
        parts = []
        if misaligned:
            parts.append(f"{misaligned}/{len(scenes)} scene cuts misaligned with keyframes")
        if cluster_segments:
            parts.append(f"{len(cluster_segments)} suspicious scene clusters")
        summary = "; ".join(parts)

    all_segments = misaligned_segments + cluster_segments
    all_segments.sort(key=lambda s: s.start_s)

    return CheckResult(
        name="scene_cut_forensics",
        category="timing",
        score=score,
        confidence=clamp01(0.55 + min(len(scenes), 50) / 100.0),
        summary=summary,
        details={
            "scene_count": len(scenes),
            "keyframe_count": len(keyframe_times),
            "gop_interval_s": round(gop_interval, 4),
            "misaligned_count": misaligned,
            "misalign_rate": round(misalign_rate, 4),
            "cluster_count": len(cluster_segments),
        },
        segments=all_segments[:120],
    )


def audio_spectral_checks(video_path: str, basic_probe: dict[str, Any]) -> CheckResult:
    """Analyze audio spectral continuity to detect splices and re-encoding artifacts.

    Computes short-time spectral features (energy, centroid, bandwidth) over sliding
    windows and detects abrupt discontinuities that may indicate audio splicing.
    """
    import tempfile
    import os

    audio_stream = _extract_audio_stream(basic_probe)
    if not audio_stream:
        return CheckResult(
            name="audio_spectral_continuity",
            category="audio",
            score=0.0,
            confidence=0.05,
            summary="No audio stream found.",
            details={},
        )

    try:
        import numpy as np
    except ImportError:
        return CheckResult(
            name="audio_spectral_continuity",
            category="audio",
            score=0.0,
            confidence=0.01,
            summary="NumPy not available for spectral analysis.",
            details={},
        )

    # Extract audio to temp WAV
    tmp_wav = tempfile.mktemp(suffix=".wav", prefix="qvk_audio_")
    try:
        sample_rate = 16000
        ok = extract_audio_pcm(video_path, tmp_wav, sample_rate=sample_rate)
        if not ok or not os.path.exists(tmp_wav) or os.path.getsize(tmp_wav) < 100:
            return CheckResult(
                name="audio_spectral_continuity",
                category="audio",
                score=0.0,
                confidence=0.1,
                summary="Audio extraction failed.",
                details={},
            )

        # Read WAV raw data (skip 44-byte header)
        with open(tmp_wav, "rb") as f:
            raw = f.read()
        if len(raw) < 44 + 1024:
            return CheckResult(
                name="audio_spectral_continuity",
                category="audio",
                score=0.0,
                confidence=0.1,
                summary="Audio too short for spectral analysis.",
                details={},
            )
        samples = np.frombuffer(raw[44:], dtype=np.int16).astype(np.float32) / 32768.0
    finally:
        try:
            os.unlink(tmp_wav)
        except OSError:
            pass

    # Compute spectral features over short windows
    hop_size = int(sample_rate * 0.05)  # 50ms hop
    window_size = int(sample_rate * 0.1)  # 100ms window
    n_windows = (len(samples) - window_size) // hop_size
    if n_windows < 10:
        return CheckResult(
            name="audio_spectral_continuity",
            category="audio",
            score=0.0,
            confidence=0.15,
            summary="Audio too short for meaningful spectral analysis.",
            details={"n_windows": n_windows},
        )

    # Compute per-window features: RMS energy, spectral centroid, zero-crossing rate
    energies = np.zeros(n_windows)
    centroids = np.zeros(n_windows)
    zcr_values = np.zeros(n_windows)

    for i in range(n_windows):
        start = i * hop_size
        window = samples[start : start + window_size]
        # RMS energy
        energies[i] = float(np.sqrt(np.mean(window ** 2)))
        # Zero-crossing rate
        zcr_values[i] = float(np.sum(np.abs(np.diff(np.sign(window)))) / (2 * len(window)))
        # Spectral centroid via FFT
        spectrum = np.abs(np.fft.rfft(window * np.hanning(len(window))))
        freqs = np.fft.rfftfreq(len(window), 1.0 / sample_rate)
        total = np.sum(spectrum)
        if total > 1e-9:
            centroids[i] = float(np.sum(freqs * spectrum) / total)

    # Detect discontinuities: abrupt jumps in energy or spectral centroid
    segments: list[SegmentEvidence] = []
    findings: list[tuple[str, float]] = []

    for name, series in [("energy", energies), ("spectral_centroid", centroids), ("zcr", zcr_values)]:
        if len(series) < 5:
            continue
        deltas = np.abs(np.diff(series))
        if len(deltas) < 3:
            continue
        med_delta = float(np.median(deltas))
        mad_delta = float(np.median(np.abs(deltas - med_delta)))
        if mad_delta < 1e-12:
            mad_delta = float(np.std(deltas)) * 0.5
        if mad_delta < 1e-12:
            continue

        threshold_z = 5.0
        for idx in range(len(deltas)):
            z = (deltas[idx] - med_delta) / (1.4826 * mad_delta + 1e-9)
            if z > threshold_z:
                ts = (idx * hop_size) / sample_rate
                segments.append(SegmentEvidence(
                    category="audio_spectral_break",
                    start_s=max(0, ts - 0.1),
                    end_s=ts + 0.1,
                    confidence=clamp01(0.5 + z / 20.0),
                    details={"feature": name, "z_score": round(float(z), 2)},
                ))
                findings.append((f"audio {name} discontinuity at {ts:.2f}s", clamp01(z / 10.0)))

    # Also check for silence gaps that could indicate splices
    silence_threshold = 0.005
    in_silence = False
    silence_start = 0.0
    for i in range(n_windows):
        ts = (i * hop_size) / sample_rate
        if energies[i] < silence_threshold:
            if not in_silence:
                silence_start = ts
                in_silence = True
        else:
            if in_silence:
                silence_dur = ts - silence_start
                if 0.05 < silence_dur < 0.5:  # suspicious short silence gap
                    segments.append(SegmentEvidence(
                        category="audio_silence_gap",
                        start_s=silence_start,
                        end_s=ts,
                        confidence=0.55,
                        details={"duration_s": round(silence_dur, 4)},
                    ))
                    findings.append((f"short silence gap at {silence_start:.2f}s ({silence_dur:.3f}s)", 0.3))
                in_silence = False

    segments.sort(key=lambda s: s.start_s)

    if not findings:
        score = 0.05
        summary = "Audio spectral characteristics are continuous and consistent."
    else:
        score = clamp01(sum(w for _, w in findings) / max(len(findings), 1))
        summary = "; ".join(f for f, _ in findings[:3])
        if len(findings) > 3:
            summary += f" (+{len(findings) - 3} more)"

    duration_s = len(samples) / sample_rate
    confidence = clamp01(0.45 + min(duration_s, 60.0) / 120.0)
    return CheckResult(
        name="audio_spectral_continuity",
        category="audio",
        score=score,
        confidence=confidence,
        summary=summary,
        details={
            "n_windows": n_windows,
            "audio_duration_s": round(duration_s, 3),
            "spectral_break_count": sum(1 for s in segments if s.category == "audio_spectral_break"),
            "silence_gap_count": sum(1 for s in segments if s.category == "audio_silence_gap"),
            "mean_energy": round(float(np.mean(energies)), 6),
            "mean_spectral_centroid_hz": round(float(np.mean(centroids)), 1),
        },
        segments=segments[:150],
    )


def temporal_noise_consistency_checks(
    video_path: str, duration_s: float, fps_hint: float, options: AnalysisOptions
) -> CheckResult:
    """Measure per-frame noise levels to detect source changes.

    Different cameras/encoders produce different noise floors. Splicing content from
    a different source shifts the noise profile. This check estimates noise via
    Laplacian standard deviation and high-frequency energy.
    """
    try:
        import cv2  # type: ignore
        import numpy as np
    except ImportError:
        return CheckResult(
            name="temporal_noise_consistency",
            category="quality",
            score=0.0,
            confidence=0.01,
            summary="OpenCV not available for noise analysis.",
            details={},
        )

    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        return CheckResult(
            name="temporal_noise_consistency",
            category="quality",
            score=0.0,
            confidence=0.05,
            summary="Cannot open video for noise analysis.",
            details={},
        )

    native_fps = cap.get(cv2.CAP_PROP_FPS) or fps_hint or 30.0
    # Sample at ~2 fps for noise analysis
    sample_stride = max(1, int(round(native_fps / 2.0)))
    max_frames = min(options.max_frames, 3000)

    noise_levels: list[float] = []
    hf_energies: list[float] = []
    timestamps: list[float] = []
    frame_idx = -1
    sampled = 0

    while sampled < max_frames:
        ok = cap.grab()
        if not ok:
            break
        frame_idx += 1
        if frame_idx % sample_stride != 0:
            continue
        ok, frame = cap.retrieve()
        if not ok or frame is None:
            continue

        ts = cap.get(cv2.CAP_PROP_POS_MSEC) / 1000.0
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        small = cv2.resize(gray, (320, 180), interpolation=cv2.INTER_AREA)

        # Noise estimate via Laplacian std dev
        lap = cv2.Laplacian(small, cv2.CV_64F)
        noise = float(np.std(lap))
        noise_levels.append(noise)

        # High-frequency energy via Sobel
        sx = cv2.Sobel(small, cv2.CV_64F, 1, 0, ksize=3)
        sy = cv2.Sobel(small, cv2.CV_64F, 0, 1, ksize=3)
        hf = float(np.mean(np.sqrt(sx ** 2 + sy ** 2)))
        hf_energies.append(hf)
        timestamps.append(ts)
        sampled += 1

    cap.release()

    if sampled < 10:
        return CheckResult(
            name="temporal_noise_consistency",
            category="quality",
            score=0.0,
            confidence=0.1,
            summary="Too few frames for noise consistency analysis.",
            details={"sampled_frames": sampled},
        )

    # Detect abrupt shifts in noise level
    segments: list[SegmentEvidence] = []
    findings: list[tuple[str, float]] = []

    for feat_name, series in [("noise_floor", noise_levels), ("hf_energy", hf_energies)]:
        arr = np.array(series)
        deltas = np.abs(np.diff(arr))
        if len(deltas) < 5:
            continue
        med_d = float(np.median(deltas))
        mad_d = float(np.median(np.abs(deltas - med_d)))
        if mad_d < 1e-9:
            mad_d = float(np.std(deltas)) * 0.5
        if mad_d < 1e-9:
            continue

        for i in range(len(deltas)):
            z = (deltas[i] - med_d) / (1.4826 * mad_d + 1e-9)
            if z > 4.5:
                ts = timestamps[i + 1] if (i + 1) < len(timestamps) else timestamps[-1]
                segments.append(SegmentEvidence(
                    category="noise_shift",
                    start_s=max(0, ts - 0.5),
                    end_s=ts + 0.5,
                    confidence=clamp01(0.55 + z / 15.0),
                    details={"feature": feat_name, "z_score": round(float(z), 2)},
                ))
                findings.append((f"{feat_name} shift at {ts:.1f}s (z={z:.1f})", clamp01(z / 10.0)))

    # Also check global consistency: split into halves and compare distributions
    half = len(noise_levels) // 2
    if half >= 5:
        first_half = np.array(noise_levels[:half])
        second_half = np.array(noise_levels[half:])
        mean_diff = abs(float(np.mean(first_half)) - float(np.mean(second_half)))
        global_std = float(np.std(noise_levels))
        if global_std > 0 and mean_diff / global_std > 1.5:
            findings.append((
                f"noise floor shift between halves (diff/std={mean_diff / global_std:.2f})",
                clamp01((mean_diff / global_std - 1.5) / 2.0),
            ))

    segments.sort(key=lambda s: s.start_s)

    if not findings:
        score = 0.05
        summary = "Noise characteristics are consistent across the video."
    else:
        score = clamp01(sum(w for _, w in findings) / max(len(findings), 1))
        summary = "; ".join(f for f, _ in findings[:3])

    return CheckResult(
        name="temporal_noise_consistency",
        category="quality",
        score=score,
        confidence=clamp01(0.45 + min(sampled, 2000) / 4000.0),
        summary=summary,
        details={
            "sampled_frames": sampled,
            "mean_noise_level": round(float(np.mean(noise_levels)), 2),
            "noise_level_std": round(float(np.std(noise_levels)), 2),
            "shift_events": len(segments),
        },
        segments=segments[:100],
    )


def double_compression_detection(
    frame_probe: dict[str, Any], packet_probe: dict[str, Any], fps_hint: float
) -> CheckResult:
    """Detect double (re-)compression by analyzing I-frame size periodicity.

    When a video is re-encoded, the original GOP cadence leaves a periodic
    fingerprint in I-frame sizes even after recompression. If the detected
    periodicity differs from the current GOP interval, it suggests the video
    was re-encoded with a different GOP setting, which is a strong indicator
    of tampering or at minimum re-processing.
    """
    frames = frame_probe.get("frames", [])

    # Gather I-frame and P-frame sizes
    i_sizes: list[tuple[int, int]] = []  # (frame_index, size)
    p_sizes: list[tuple[int, int]] = []
    all_sizes: list[int] = []

    for idx, frame in enumerate(frames):
        size = int(to_float(frame.get("pkt_size")) or 0)
        ptype = (frame.get("pict_type") or "?")[0].upper()
        all_sizes.append(size)
        if ptype == "I":
            i_sizes.append((idx, size))
        elif ptype == "P":
            p_sizes.append((idx, size))

    if len(i_sizes) < 4 or len(all_sizes) < 50:
        return CheckResult(
            name="double_compression_detection",
            category="codec",
            score=0.0,
            confidence=0.05,
            summary="Insufficient I-frame data for double compression analysis.",
            details={},
        )

    try:
        import numpy as np
    except ImportError:
        return CheckResult(
            name="double_compression_detection",
            category="codec",
            score=0.0,
            confidence=0.01,
            summary="NumPy not available.",
            details={},
        )

    # Current GOP interval (from I-frame indices)
    gop_intervals = [i_sizes[i][0] - i_sizes[i - 1][0] for i in range(1, len(i_sizes))]
    current_gop = int(median(gop_intervals)) if gop_intervals else 30

    # Analyze P-frame size periodicity using autocorrelation
    # In a doubly-compressed video, P-frame sizes show periodic peaks
    # at the original GOP interval
    if len(p_sizes) > 60:
        p_size_series = np.array([s for _, s in p_sizes], dtype=np.float64)
        p_size_series = p_size_series - np.mean(p_size_series)
        norm = np.sum(p_size_series ** 2)
        if norm > 0:
            autocorr = np.correlate(p_size_series, p_size_series, mode="full")
            autocorr = autocorr[len(autocorr) // 2 :] / norm
            # Look for secondary peaks (skip lag 0 and lags near current GOP)
            search_range = autocorr[2 : min(len(autocorr), max(current_gop * 3, 120))]
            if len(search_range) > 10:
                # Find peaks above noise floor
                noise_floor = float(np.std(search_range))
                peaks = []
                for i in range(1, len(search_range) - 1):
                    if search_range[i] > search_range[i - 1] and search_range[i] > search_range[i + 1]:
                        if search_range[i] > noise_floor * 2.5:
                            lag = i + 2  # offset by our start position
                            peaks.append((lag, float(search_range[i])))

                # Check if any peak lag doesn't match current GOP
                suspicious_peaks = []
                for lag, strength in peaks:
                    # If this lag doesn't align with the current GOP
                    if current_gop > 0 and abs(lag % current_gop) > 2 and abs(lag % current_gop - current_gop) > 2:
                        suspicious_peaks.append((lag, strength))

                if suspicious_peaks:
                    strongest = max(suspicious_peaks, key=lambda x: x[1])
                    score = clamp01(strongest[1] * 1.5)
                    return CheckResult(
                        name="double_compression_detection",
                        category="codec",
                        score=score,
                        confidence=clamp01(0.55 + min(len(p_sizes), 500) / 1000.0),
                        summary=f"Periodic pattern at lag {strongest[0]} suggests prior encoding with different GOP (current GOP={current_gop}).",
                        details={
                            "current_gop": current_gop,
                            "suspicious_lags": [(l, round(s, 4)) for l, s in suspicious_peaks[:5]],
                            "i_frame_count": len(i_sizes),
                            "p_frame_count": len(p_sizes),
                        },
                    )

    # Also check I-frame size regularity: in doubly-compressed video,
    # I-frames that fall on original I-frame positions have different sizes
    if len(i_sizes) >= 6:
        i_size_values = np.array([s for _, s in i_sizes], dtype=np.float64)
        i_mean = float(np.mean(i_size_values))
        i_std = float(np.std(i_size_values))
        i_cv = i_std / max(i_mean, 1.0)
        # High I-frame size variation can indicate double compression
        if i_cv > 0.45:
            score = clamp01((i_cv - 0.45) / 0.5)
            return CheckResult(
                name="double_compression_detection",
                category="codec",
                score=score,
                confidence=clamp01(0.4 + min(len(i_sizes), 30) / 60.0),
                summary=f"I-frame size variation is unusually high (CV={i_cv:.2f}), suggesting possible re-encoding.",
                details={
                    "current_gop": current_gop,
                    "i_frame_count": len(i_sizes),
                    "i_frame_size_cv": round(i_cv, 4),
                    "i_frame_mean_size": round(i_mean, 0),
                },
            )

    return CheckResult(
        name="double_compression_detection",
        category="codec",
        score=0.05,
        confidence=clamp01(0.5 + min(len(i_sizes), 30) / 60.0),
        summary="No strong evidence of double compression detected.",
        details={
            "current_gop": current_gop,
            "i_frame_count": len(i_sizes),
            "p_frame_count": len(p_sizes),
        },
    )


def ela_frame_analysis(
    video_path: str, duration_s: float, fps_hint: float, options: AnalysisOptions
) -> CheckResult:
    """Error Level Analysis (ELA) on sampled video frames.

    Re-compresses sampled frames at a fixed quality and measures the residual
    (difference between original decoded frame and re-compressed version).
    Tampered regions typically show different error levels than the surrounding content.
    """
    try:
        import cv2  # type: ignore
        import numpy as np
    except ImportError:
        return CheckResult(
            name="ela_frame_analysis",
            category="quality",
            score=0.0,
            confidence=0.01,
            summary="OpenCV not available for ELA.",
            details={},
        )

    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        return CheckResult(
            name="ela_frame_analysis",
            category="quality",
            score=0.0,
            confidence=0.05,
            summary="Cannot open video for ELA.",
            details={},
        )

    native_fps = cap.get(cv2.CAP_PROP_FPS) or fps_hint or 30.0
    # Sample fewer frames for ELA since it's computationally expensive
    sample_stride = max(1, int(round(native_fps / 1.5)))
    max_frames = min(options.max_frames // 2, 1500)

    ela_means: list[float] = []
    ela_stds: list[float] = []
    ela_maxes: list[float] = []
    timestamps: list[float] = []
    frame_idx = -1
    sampled = 0

    while sampled < max_frames:
        ok = cap.grab()
        if not ok:
            break
        frame_idx += 1
        if frame_idx % sample_stride != 0:
            continue
        ok, frame = cap.retrieve()
        if not ok or frame is None:
            continue

        ts = cap.get(cv2.CAP_PROP_POS_MSEC) / 1000.0
        small = cv2.resize(frame, (320, 180), interpolation=cv2.INTER_AREA)

        # Re-compress at quality 75 (JPEG)
        encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), 75]
        _, enc = cv2.imencode(".jpg", small, encode_param)
        recompressed = cv2.imdecode(enc, cv2.IMREAD_COLOR)

        # Compute residual
        diff = np.abs(small.astype(np.float32) - recompressed.astype(np.float32))
        ela_means.append(float(np.mean(diff)))
        ela_stds.append(float(np.std(diff)))
        ela_maxes.append(float(np.max(diff)))
        timestamps.append(ts)
        sampled += 1

    cap.release()

    if sampled < 10:
        return CheckResult(
            name="ela_frame_analysis",
            category="quality",
            score=0.0,
            confidence=0.1,
            summary="Too few frames for ELA analysis.",
            details={"sampled_frames": sampled},
        )

    arr_means = ela_means
    arr_stds = ela_stds

    # Detect abrupt shifts in ELA residuals
    segments: list[SegmentEvidence] = []
    findings: list[tuple[str, float]] = []

    for feat_name, series in [("ela_mean", arr_means), ("ela_std", arr_stds)]:
        deltas = [abs(series[i] - series[i - 1]) for i in range(1, len(series))]
        if len(deltas) < 5:
            continue
        med_d = median(deltas)
        mad_d = _mad(deltas, fallback=1.0)

        for i, d in enumerate(deltas):
            z = (d - med_d) / (1.4826 * mad_d + 1e-9)
            if z > 4.0:
                ts = timestamps[i + 1] if (i + 1) < len(timestamps) else timestamps[-1]
                segments.append(SegmentEvidence(
                    category="ela_shift",
                    start_s=max(0, ts - 0.5),
                    end_s=ts + 0.5,
                    confidence=clamp01(0.5 + z / 15.0),
                    details={"feature": feat_name, "z_score": round(z, 2)},
                ))
                findings.append((f"ELA {feat_name} shift at {ts:.1f}s (z={z:.1f})", clamp01(z / 10.0)))

    # Check spatial consistency: compare ELA distributions across frame regions
    # (would need per-region analysis, simplified here to temporal)
    global_ela_mean = sum(arr_means) / len(arr_means)
    global_ela_std = (sum((x - global_ela_mean) ** 2 for x in arr_means) / len(arr_means)) ** 0.5

    # High temporal variance in ELA residuals suggests mixed compression
    ela_cv = global_ela_std / max(global_ela_mean, 1e-6)
    if ela_cv > 0.35:
        findings.append((f"high ELA residual variance (CV={ela_cv:.2f})", clamp01((ela_cv - 0.35) / 0.5)))

    segments.sort(key=lambda s: s.start_s)

    if not findings:
        score = 0.05
        summary = "ELA residuals are consistent across frames."
    else:
        score = clamp01(sum(w for _, w in findings) / max(len(findings), 1))
        summary = "; ".join(f for f, _ in findings[:3])

    return CheckResult(
        name="ela_frame_analysis",
        category="quality",
        score=score,
        confidence=clamp01(0.4 + min(sampled, 1000) / 2000.0),
        summary=summary,
        details={
            "sampled_frames": sampled,
            "mean_ela_residual": round(global_ela_mean, 3),
            "ela_residual_cv": round(ela_cv, 4),
            "shift_events": len(segments),
        },
        segments=segments[:100],
    )


def bitstream_structure_checks(
    video_path: str, basic_probe: dict[str, Any], frame_probe: dict[str, Any]
) -> CheckResult:
    """Analyze codec bitstream structure for splicing indicators.

    Checks for mid-stream parameter changes (SPS/PPS for H.264, VPS/SPS/PPS for H.265),
    unusual NAL unit patterns, and codec profile/level inconsistencies that indicate
    content was concatenated from different encoding sessions.
    """
    video_stream = _extract_video_stream(basic_probe)
    if not video_stream:
        return CheckResult(
            name="bitstream_structure",
            category="codec",
            score=0.0,
            confidence=0.05,
            summary="No video stream found.",
            details={},
        )

    codec = (video_stream.get("codec_name") or "").lower()
    profile = video_stream.get("profile", "")
    level = video_stream.get("level", "")

    frames = frame_probe.get("frames", [])
    if not frames:
        return CheckResult(
            name="bitstream_structure",
            category="codec",
            score=0.0,
            confidence=0.1,
            summary="No frame data available for bitstream analysis.",
            details={"codec": codec},
        )

    findings: list[tuple[str, float]] = []
    segments: list[SegmentEvidence] = []
    details: dict[str, Any] = {
        "codec": codec,
        "profile": profile,
        "level": level,
        "frame_count": len(frames),
    }

    # Check for mid-stream changes in color parameters
    color_params: list[tuple[float, tuple[str | None, str | None, str | None]]] = []
    for frame in frames:
        ts = to_float(frame.get("best_effort_timestamp_time")) or 0.0
        params = (
            frame.get("color_space"),
            frame.get("color_transfer"),
            frame.get("color_primaries"),
        )
        color_params.append((ts, params))

    if len(color_params) > 1:
        unique_params = set(p for _, p in color_params if any(p))
        if len(unique_params) > 1:
            # Find transition points
            prev_params = color_params[0][1]
            for ts, params in color_params[1:]:
                if any(params) and params != prev_params and any(prev_params):
                    findings.append((f"color parameter change at {ts:.2f}s", 0.6))
                    segments.append(SegmentEvidence(
                        category="bitstream_param_change",
                        start_s=max(0, ts - 0.2),
                        end_s=ts + 0.2,
                        confidence=0.75,
                        details={"old": list(prev_params), "new": list(params)},
                    ))
                if any(params):
                    prev_params = params
            details["color_param_variants"] = len(unique_params)

    # Check for interlaced/progressive mode changes
    interlace_values = [int(frame.get("interlaced_frame") or 0) for frame in frames]
    unique_interlace = set(interlace_values)
    if len(unique_interlace) > 1:
        findings.append(("mixed interlaced/progressive frames", 0.5))
        details["mixed_interlacing"] = True

    # Check for frame size anomalies per picture type
    # (different encoding sessions produce different size distributions per type)
    type_sizes: dict[str, list[int]] = {}
    for frame in frames:
        ptype = (frame.get("pict_type") or "?")[0].upper()
        size = int(to_float(frame.get("pkt_size")) or 0)
        if ptype in ("I", "P", "B"):
            type_sizes.setdefault(ptype, []).append(size)

    for ptype, sizes in type_sizes.items():
        if len(sizes) < 10:
            continue
        sorted_sizes = sorted(sizes)
        q1 = sorted_sizes[len(sorted_sizes) // 4]
        q3 = sorted_sizes[3 * len(sorted_sizes) // 4]
        iqr = q3 - q1
        lower = q1 - 3.0 * iqr
        upper = q3 + 3.0 * iqr
        outlier_count = sum(1 for s in sizes if s < lower or s > upper)
        outlier_rate = outlier_count / len(sizes)
        if outlier_rate > 0.05:
            findings.append((
                f"{ptype}-frame size outlier rate={outlier_rate:.1%}",
                clamp01((outlier_rate - 0.05) / 0.15),
            ))
            details[f"{ptype}_frame_outlier_rate"] = round(outlier_rate, 4)

    # Check extradata_size consistency (different for different encoding sessions)
    extradata = to_float(video_stream.get("extradata_size"))
    if extradata is not None:
        details["extradata_size"] = int(extradata)
    # has_b_frames inconsistency check
    has_b = video_stream.get("has_b_frames")
    actual_b = len(type_sizes.get("B", []))
    if has_b is not None:
        details["declared_b_frames"] = int(has_b)
        details["actual_b_frame_count"] = actual_b
        if int(has_b) == 0 and actual_b > 0:
            findings.append(("B-frames present despite has_b_frames=0", 0.4))
        elif int(has_b) > 0 and actual_b == 0:
            findings.append(("no B-frames found despite has_b_frames declared", 0.25))

    segments.sort(key=lambda s: s.start_s)

    if not findings:
        score = 0.05
        summary = "Bitstream structure is consistent throughout."
    else:
        score = clamp01(sum(w for _, w in findings) / max(len(findings), 1))
        summary = "; ".join(f for f, _ in findings[:3])

    confidence = clamp01(0.5 + min(len(frames), 3000) / 6000.0)
    return CheckResult(
        name="bitstream_structure",
        category="codec",
        score=score,
        confidence=confidence,
        summary=summary,
        details=details,
        segments=segments[:80],
    )


_FFPROBE_NOT_FOUND_MSG = "ffprobe not found. Install ffmpeg to enable this check."


def analyze_video(path: str, options: AnalysisOptions | None = None) -> AnalysisResult:
    opts = AnalysisOptions.from_dict(asdict(options)) if options else AnalysisOptions()
    started = now_utc_iso()

    checks: list[CheckResult] = []
    debug_payload: dict[str, Any] = {"probe_errors": []}

    ffprobe_available = True
    try:
        basic_probe = build_basic_probe(path)
    except FileNotFoundError:
        basic_probe = {}
        ffprobe_available = False
        debug_payload["probe_errors"].append(_FFPROBE_NOT_FOUND_MSG)
    except FFProbeError as exc:
        basic_probe = {}
        debug_payload["probe_errors"].append(f"basic_probe: {exc}")

    video_stream = _extract_video_stream(basic_probe)
    duration_s = _extract_duration(basic_probe, video_stream)
    fps_hint = _extract_fps(video_stream)

    if opts.enable_metadata_scan:
        if not ffprobe_available:
            checks.append(
                CheckResult(
                    name="metadata_codec_consistency",
                    category="metadata",
                    score=0.0,
                    confidence=0.1,
                    summary=_FFPROBE_NOT_FOUND_MSG,
                    details={},
                )
            )
        else:
            checks.append(metadata_codec_checks(basic_probe))

    packet_probe = {}
    if opts.enable_packet_scan:
        if not ffprobe_available:
            checks.append(
                CheckResult(
                    name="packet_timing_anomalies",
                    category="timing",
                    score=0.0,
                    confidence=0.1,
                    summary=_FFPROBE_NOT_FOUND_MSG,
                    details={},
                )
            )
        else:
            try:
                packet_probe = build_packet_probe(path, timeout=240 if opts.preset == "deep" else 120)
                checks.append(packet_timing_checks(packet_probe, fps_hint=fps_hint))
            except FileNotFoundError:
                debug_payload["probe_errors"].append(f"packet_probe: {_FFPROBE_NOT_FOUND_MSG}")
            except FFProbeError as exc:
                debug_payload["probe_errors"].append(f"packet_probe: {exc}")

    frame_probe = {}
    if opts.enable_frame_scan:
        if not ffprobe_available:
            checks.append(
                CheckResult(
                    name="frame_structure_anomalies",
                    category="codec",
                    score=0.0,
                    confidence=0.1,
                    summary=_FFPROBE_NOT_FOUND_MSG,
                    details={},
                )
            )
        else:
            try:
                frame_probe = build_frame_probe(path, timeout=240 if opts.preset == "deep" else 120)
                checks.append(frame_structure_checks(frame_probe))
            except FileNotFoundError:
                debug_payload["probe_errors"].append(f"frame_probe: {_FFPROBE_NOT_FOUND_MSG}")
            except FFProbeError as exc:
                debug_payload["probe_errors"].append(f"frame_probe: {exc}")

    if opts.enable_quality_scan:
        try:
            checks.append(opencv_frame_quality_checks(path, duration_s=duration_s, fps_hint=fps_hint, options=opts))
        except Exception as exc:  # pragma: no cover - resilience path
            debug_payload["probe_errors"].append(f"opencv_frame_quality_checks: {exc}")
            checks.append(
                CheckResult(
                    name="frame_quality_shift",
                    category="quality",
                    score=0.0,
                    confidence=0.05,
                    summary="Frame quality analysis failed and was skipped.",
                    details={"error": str(exc)},
                )
            )

    # ── Advanced forensic checks (enabled for deep preset or explicitly) ─────
    if opts.enable_advanced_forensics:
        # 1. Compression consistency (requires frame + packet data)
        if frame_probe or packet_probe:
            try:
                checks.append(compression_consistency_checks(frame_probe, packet_probe, duration_s))
            except Exception as exc:
                debug_payload["probe_errors"].append(f"compression_consistency: {exc}")

        # 2. Scene cut forensics (requires ffmpeg scene detection + frame data)
        if ffprobe_available:
            try:
                checks.append(scene_cut_forensics_checks(path, basic_probe, frame_probe, fps_hint, duration_s))
            except Exception as exc:
                debug_payload["probe_errors"].append(f"scene_cut_forensics: {exc}")

        # 3. Audio spectral continuity
        try:
            checks.append(audio_spectral_checks(path, basic_probe))
        except Exception as exc:
            debug_payload["probe_errors"].append(f"audio_spectral_continuity: {exc}")

        # 4. Temporal noise consistency (OpenCV-based)
        try:
            checks.append(temporal_noise_consistency_checks(path, duration_s, fps_hint, opts))
        except Exception as exc:
            debug_payload["probe_errors"].append(f"temporal_noise_consistency: {exc}")

        # 5. Double compression detection
        if frame_probe or packet_probe:
            try:
                checks.append(double_compression_detection(frame_probe, packet_probe, fps_hint))
            except Exception as exc:
                debug_payload["probe_errors"].append(f"double_compression_detection: {exc}")

        # 6. ELA frame analysis (OpenCV-based)
        try:
            checks.append(ela_frame_analysis(path, duration_s, fps_hint, opts))
        except Exception as exc:
            debug_payload["probe_errors"].append(f"ela_frame_analysis: {exc}")

        # 7. Bitstream structure analysis
        if ffprobe_available and frame_probe:
            try:
                checks.append(bitstream_structure_checks(path, basic_probe, frame_probe))
            except Exception as exc:
                debug_payload["probe_errors"].append(f"bitstream_structure: {exc}")

    tamper_probability, confidence, label = fuse_scores(checks, sensitivity=opts.sensitivity)

    all_segments: list[SegmentEvidence] = []
    for check in checks:
        all_segments.extend(check.segments)
    all_segments.sort(key=lambda segment: (segment.start_s, segment.end_s))

    strongest = sorted(checks, key=lambda c: c.score * c.confidence, reverse=True)[:5]
    explanation = []
    if label == "authentic":
        explanation.append("No strong tampering indicators were found in the enabled checks.")
    elif label == "inconclusive":
        explanation.append("Evidence quality was not high enough for a definitive decision.")
    else:
        explanation.append(
            "Multiple forensic signals suggest possible alteration, especially in the highest scoring checks."
        )
    for check in strongest:
        if check.score < 0.1:
            continue
        explanation.append(
            f"{check.name}: {check.summary} (score={check.score:.2f}, confidence={check.confidence:.2f})"
        )

    for check in checks:
        if check.score == 0.0 and check.confidence <= 0.05 and check.summary:
            note = f"Note: {check.summary}"
            if note not in explanation:
                explanation.append(note)

    finished = now_utc_iso()
    debug = {}
    if opts.include_debug_payload:
        debug = {
            "basic_probe": basic_probe,
            "packet_probe": packet_probe,
            "frame_probe": frame_probe,
            **debug_payload,
        }
    else:
        debug = debug_payload

    return AnalysisResult(
        video_path=path,
        started_at_utc=started,
        finished_at_utc=finished,
        file_sha256=sha256_for_file(path),
        file_size_bytes=file_size(path),
        duration_s=duration_s,
        tamper_probability=tamper_probability,
        label=label,  # type: ignore[arg-type]
        confidence=confidence,
        checks=checks,
        suspicious_segments=all_segments[:200],
        explanation=explanation,
        options=asdict(opts),
        debug=debug,
    )
