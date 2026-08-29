from __future__ import annotations

from typing import Any

from .models import AnalysisOptions, CheckResult, SegmentEvidence
from .scoring import clamp01


def _sample_grayscale_frames(
    video_path: str, fps_hint: float, options: AnalysisOptions, max_frames_cap: int
) -> tuple[list[Any], list[float], float]:
    import cv2  # type: ignore

    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        return [], [], 0.0

    native_fps = cap.get(cv2.CAP_PROP_FPS) or fps_hint or 30.0
    sample_stride = max(1, int(round(native_fps / max(options.sample_fps, 0.2))))
    max_frames = min(options.max_frames, max_frames_cap)

    frames: list[Any] = []
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

        frames.append(small)
        timestamps.append(ts)
        sampled += 1

    cap.release()
    return frames, timestamps, native_fps


def sensor_noise_correlation_checks(
    path: str, duration_s: float, fps_hint: float, options: AnalysisOptions
) -> CheckResult:
    """Compare noise-residue signatures across temporal windows (PRNU-lite).

    Every sensor/encoder pipeline leaves a characteristic high-frequency noise
    residue. Splicing footage from a different source shows up as a drop in
    cross-correlation between the noise residue of one part of the video and
    another. This is a lightweight heuristic, not true PRNU fingerprinting.
    """
    try:
        import cv2  # type: ignore
        import numpy as np
    except ImportError:
        return CheckResult(
            name="sensor_noise_correlation",
            category="quality",
            score=0.0,
            confidence=0.01,
            summary="OpenCV not available for sensor noise correlation analysis.",
            details={"reason": "opencv-python dependency missing"},
        )

    try:
        frames, timestamps, _native_fps = _sample_grayscale_frames(path, fps_hint, options, max_frames_cap=3000)
    except Exception as exc:
        return CheckResult(
            name="sensor_noise_correlation",
            category="quality",
            score=0.0,
            confidence=0.05,
            summary="Sensor noise correlation analysis failed during frame sampling.",
            details={"error": str(exc)},
        )

    if len(frames) < 10:
        return CheckResult(
            name="sensor_noise_correlation",
            category="quality",
            score=0.0,
            confidence=0.1,
            summary="Too few frames for sensor noise correlation analysis.",
            details={"sampled_frames": len(frames)},
        )

    try:
        residues: list[Any] = []
        for gray in frames:
            gray_f = gray.astype("float32")
            blurred = cv2.GaussianBlur(gray_f, (3, 3), 0)
            residue = gray_f - blurred
            residues.append(residue)

        n_windows = 4 if len(residues) >= 40 else 2
        window_size = max(1, len(residues) // n_windows)
        windows: list[list[Any]] = []
        for w in range(n_windows):
            start = w * window_size
            end = len(residues) if w == n_windows - 1 else (w + 1) * window_size
            chunk = residues[start:end]
            if chunk:
                windows.append(chunk)

        if len(windows) < 2:
            return CheckResult(
                name="sensor_noise_correlation",
                category="quality",
                score=0.0,
                confidence=0.15,
                summary="Not enough temporal spread to build noise-signature windows.",
                details={"sampled_frames": len(frames)},
            )

        window_signatures = [np.mean(np.stack(chunk, axis=0), axis=0) for chunk in windows]

        correlations: list[float] = []
        pair_details: list[dict[str, Any]] = []
        for i in range(len(window_signatures) - 1):
            a = window_signatures[i].flatten()
            b = window_signatures[i + 1].flatten()
            a_centered = a - a.mean()
            b_centered = b - b.mean()
            denom = float(np.linalg.norm(a_centered) * np.linalg.norm(b_centered))
            if denom < 1e-9:
                corr = 1.0
            else:
                corr = float(np.dot(a_centered, b_centered) / denom)
            corr = max(-1.0, min(1.0, corr))
            correlations.append(corr)
            pair_details.append({"window_pair": f"{i}-{i + 1}", "correlation": round(corr, 4)})

        min_corr = min(correlations)
        mean_corr = sum(correlations) / len(correlations)

        # High correlation (near 1.0) is expected for consistent source material.
        # A drop toward 0 or negative suggests a different noise signature was spliced in.
        anomaly = clamp01((0.8 - min_corr) / 1.3)
        score = anomaly

        segments: list[SegmentEvidence] = []
        if anomaly > 0.25:
            window_dur = duration_s / max(len(windows), 1) if duration_s > 0 else 0.0
            for idx, corr in enumerate(correlations):
                if corr < 0.6:
                    start_s = idx * window_dur if window_dur > 0 else (timestamps[idx * window_size] if idx * window_size < len(timestamps) else 0.0)
                    end_s = (idx + 2) * window_dur if window_dur > 0 else duration_s
                    segments.append(
                        SegmentEvidence(
                            category="sensor_noise_discontinuity",
                            start_s=max(0.0, start_s),
                            end_s=max(start_s, end_s),
                            confidence=clamp01(0.5 + (0.6 - corr)),
                            details={"window_pair": f"{idx}-{idx + 1}", "correlation": round(corr, 4)},
                        )
                    )

        if anomaly <= 0.15:
            summary = (
                f"Noise-residue signatures are consistent across {len(windows)} temporal windows "
                f"(min correlation {min_corr:.2f}), suggesting a single source/sensor."
            )
        else:
            summary = (
                f"Noise-residue correlation drops between temporal windows "
                f"(min correlation {min_corr:.2f} of {len(windows)} windows), a possible splice indicator."
            )

        confidence = clamp01(0.35 + min(len(frames), 1500) / 3000.0)

        return CheckResult(
            name="sensor_noise_correlation",
            category="quality",
            score=score,
            confidence=confidence,
            summary=summary,
            details={
                "sampled_frames": len(frames),
                "windows": len(windows),
                "min_correlation": round(min_corr, 4),
                "mean_correlation": round(mean_corr, 4),
                "window_pair_correlations": pair_details,
                "method": "gaussian-blur noise residue, normalized cross-correlation between window-averaged signatures",
            },
            segments=segments[:50],
        )
    except Exception as exc:
        return CheckResult(
            name="sensor_noise_correlation",
            category="quality",
            score=0.0,
            confidence=0.05,
            summary="Sensor noise correlation analysis failed.",
            details={"error": str(exc)},
        )


def frequency_artifact_checks(
    path: str, duration_s: float, fps_hint: float, options: AnalysisOptions
) -> CheckResult:
    """Heuristic frequency-domain scan for GAN/diffusion upsampling artifacts.

    GAN and diffusion upsamplers frequently leave periodic checkerboard/grid
    energy in the mid/high frequency bands of the 2D FFT spectrum. This check
    also optionally tracks flicker in a detected face region as a secondary
    signal. This is a heuristic indicator only, not a deepfake classifier -
    it estimates evidence-backed likelihood, not certainty.
    """
    try:
        import cv2  # type: ignore
        import numpy as np
    except ImportError:
        return CheckResult(
            name="frequency_artifact_scan",
            category="quality",
            score=0.0,
            confidence=0.01,
            summary="OpenCV not available for frequency artifact analysis.",
            details={"reason": "opencv-python dependency missing"},
        )

    try:
        frames, timestamps, _native_fps = _sample_grayscale_frames(path, fps_hint, options, max_frames_cap=1500)
    except Exception as exc:
        return CheckResult(
            name="frequency_artifact_scan",
            category="quality",
            score=0.0,
            confidence=0.05,
            summary="Frequency artifact analysis failed during frame sampling.",
            details={"error": str(exc)},
        )

    if len(frames) < 8:
        return CheckResult(
            name="frequency_artifact_scan",
            category="quality",
            score=0.0,
            confidence=0.1,
            summary="Too few frames for frequency artifact analysis.",
            details={"sampled_frames": len(frames)},
        )

    try:
        periodicity_scores: list[float] = []
        for gray in frames:
            gray_f = gray.astype("float32")
            window = np.outer(np.hanning(gray_f.shape[0]), np.hanning(gray_f.shape[1]))
            spectrum = np.fft.fftshift(np.fft.fft2(gray_f * window))
            magnitude = np.abs(spectrum)
            magnitude = np.log1p(magnitude)

            h, w = magnitude.shape
            cy, cx = h // 2, w // 2
            yy, xx = np.mgrid[0:h, 0:w]
            radius = np.sqrt((yy - cy) ** 2 + (xx - cx) ** 2)
            max_radius = min(cy, cx)

            mid_band = (radius >= max_radius * 0.35) & (radius < max_radius * 0.75)
            high_band = radius >= max_radius * 0.75

            if not np.any(mid_band) or not np.any(high_band):
                continue

            mid_energy = magnitude[mid_band]
            high_energy = magnitude[high_band]

            # Anomalous periodicity shows up as sharp, high-magnitude peaks
            # standing well above the local mid/high-band average.
            mid_peak_ratio = float(mid_energy.max() / (mid_energy.mean() + 1e-6))
            high_peak_ratio = float(high_energy.max() / (high_energy.mean() + 1e-6))
            periodicity_scores.append(max(mid_peak_ratio, high_peak_ratio))

        fft_signal_available = len(periodicity_scores) >= 5
        fft_component = 0.0
        fft_summary = "insufficient spectrum samples"
        if fft_signal_available:
            mean_ratio = float(np.mean(periodicity_scores))
            # Typical natural-image mid/high band peak ratios sit roughly in the
            # 3-6x range; sustained values well above that are treated as anomalous.
            fft_component = clamp01((mean_ratio - 5.0) / 10.0)
            fft_summary = f"mean spectral peak ratio {mean_ratio:.2f}x across {len(periodicity_scores)} frames"
        else:
            mean_ratio = 0.0

        # Optional face-region flicker signal
        face_component = 0.0
        face_frames_used = 0
        face_summary = "no face detected in enough sampled frames; face flicker signal skipped"
        try:
            cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
            face_cascade = cv2.CascadeClassifier(cascade_path)
            if face_cascade.empty():
                raise RuntimeError("haar cascade failed to load")

            face_diffs: list[float] = []
            prev_face_patch = None
            for gray in frames:
                faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(24, 24))
                if len(faces) == 0:
                    prev_face_patch = None
                    continue
                fx, fy, fw, fh = max(faces, key=lambda f: f[2] * f[3])
                patch = cv2.resize(gray[fy : fy + fh, fx : fx + fw], (64, 64)).astype("float32")
                if prev_face_patch is not None:
                    diff = float(np.mean(np.abs(patch - prev_face_patch)) / 255.0)
                    face_diffs.append(diff)
                prev_face_patch = patch
                face_frames_used += 1

            if face_frames_used >= 6 and len(face_diffs) >= 5:
                flicker_std = float(np.std(face_diffs))
                flicker_mean = float(np.mean(face_diffs))
                # Elevated frame-to-frame variance localized to the face region,
                # relative to its own mean, suggests inconsistent regeneration.
                if flicker_mean > 1e-6:
                    coeff_var = flicker_std / flicker_mean
                    face_component = clamp01((coeff_var - 0.8) / 1.5)
                    face_summary = (
                        f"face region tracked across {face_frames_used} frames "
                        f"(flicker coefficient of variation {coeff_var:.2f})"
                    )
                else:
                    face_summary = (
                        f"face region tracked across {face_frames_used} frames but signal was too flat to score"
                    )
            else:
                face_summary = (
                    f"face detected in only {face_frames_used} of {len(frames)} sampled frames; "
                    "not enough to score flicker"
                )
        except Exception as face_exc:  # face check is optional, never fail the whole check
            face_summary = f"face flicker signal skipped: {face_exc}"

        if fft_signal_available and face_component > 0.0 and "coefficient of variation" in face_summary:
            score = clamp01(0.75 * fft_component + 0.25 * face_component)
        else:
            score = fft_component

        confidence_base = 0.3 if fft_signal_available else 0.1
        confidence = clamp01(confidence_base + min(len(frames), 1000) / 2500.0)

        if score <= 0.15:
            summary = f"No strong periodic frequency-domain artifacts detected ({fft_summary})."
        else:
            summary = (
                f"Frequency-domain heuristic found elevated mid/high-band periodicity "
                f"({fft_summary}); this is an indicator, not a deepfake classification."
            )

        return CheckResult(
            name="frequency_artifact_scan",
            category="quality",
            score=score,
            confidence=confidence,
            summary=summary,
            details={
                "sampled_frames": len(frames),
                "fft_frames_analyzed": len(periodicity_scores),
                "mean_spectral_peak_ratio": round(mean_ratio, 4) if fft_signal_available else None,
                "fft_component_score": round(fft_component, 4),
                "face_flicker_component_score": round(face_component, 4),
                "face_frames_used": face_frames_used,
                "face_signal_summary": face_summary,
                "method": "2D FFT mid/high-band peak-to-mean ratio; optional Haar-cascade face-region flicker",
                "disclaimer": (
                    "Heuristic frequency-domain indicator only. Does not constitute a deepfake "
                    "or GAN-generation classification."
                ),
            },
            segments=[],
        )
    except Exception as exc:
        return CheckResult(
            name="frequency_artifact_scan",
            category="quality",
            score=0.0,
            confidence=0.05,
            summary="Frequency artifact analysis failed.",
            details={"error": str(exc)},
        )
