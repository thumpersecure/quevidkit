from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict
from statistics import median
from typing import Any

from .ffprobe_utils import (
    FFProbeError,
    build_basic_probe,
    build_frame_probe,
    build_packet_probe,
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


def analyze_video(path: str, options: AnalysisOptions | None = None) -> AnalysisResult:
    opts = AnalysisOptions.from_dict(asdict(options)) if options else AnalysisOptions()
    started = now_utc_iso()

    basic_probe = build_basic_probe(path)
    video_stream = _extract_video_stream(basic_probe)
    duration_s = _extract_duration(basic_probe, video_stream)
    fps_hint = _extract_fps(video_stream)

    checks: list[CheckResult] = []
    debug_payload: dict[str, Any] = {"probe_errors": []}

    if opts.enable_metadata_scan:
        checks.append(metadata_codec_checks(basic_probe))

    packet_probe = {}
    if opts.enable_packet_scan:
        try:
            packet_probe = build_packet_probe(path, timeout=240 if opts.preset == "deep" else 120)
            checks.append(packet_timing_checks(packet_probe, fps_hint=fps_hint))
        except FFProbeError as exc:
            debug_payload["probe_errors"].append(f"packet_probe: {exc}")

    frame_probe = {}
    if opts.enable_frame_scan:
        try:
            frame_probe = build_frame_probe(path, timeout=240 if opts.preset == "deep" else 120)
            checks.append(frame_structure_checks(frame_probe))
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
