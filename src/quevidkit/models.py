from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
import hashlib
import json
import os


DecisionLabel = Literal["authentic", "suspicious", "tampered", "inconclusive"]


@dataclass
class SegmentEvidence:
    category: str
    start_s: float
    end_s: float
    confidence: float
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["start_s"] = round(self.start_s, 3)
        data["end_s"] = round(self.end_s, 3)
        data["confidence"] = round(self.confidence, 4)
        return data


@dataclass
class CheckResult:
    name: str
    category: str
    score: float
    confidence: float
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    segments: list[SegmentEvidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "score": round(self.score, 4),
            "confidence": round(self.confidence, 4),
            "summary": self.summary,
            "details": self.details,
            "segments": [segment.to_dict() for segment in self.segments],
        }


@dataclass
class AnalysisOptions:
    preset: Literal["fast", "balanced", "deep"] = "balanced"
    sample_fps: float = 2.0
    max_frames: int = 2000
    sensitivity: float = 0.7
    enable_metadata_scan: bool = True
    enable_packet_scan: bool = True
    enable_frame_scan: bool = True
    enable_quality_scan: bool = True
    include_debug_payload: bool = False

    @staticmethod
    def from_dict(payload: dict[str, Any] | None) -> "AnalysisOptions":
        if not payload:
            return AnalysisOptions()
        known = {
            "preset",
            "sample_fps",
            "max_frames",
            "sensitivity",
            "enable_metadata_scan",
            "enable_packet_scan",
            "enable_frame_scan",
            "enable_quality_scan",
            "include_debug_payload",
        }
        kwargs = {k: v for k, v in payload.items() if k in known}
        try:
            options = AnalysisOptions(**kwargs)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid options payload: {exc}") from exc
        options.apply_preset()
        try:
            options.sample_fps = max(0.2, min(30.0, float(options.sample_fps)))
            options.max_frames = max(60, min(100000, int(options.max_frames)))
            options.sensitivity = max(0.05, min(0.99, float(options.sensitivity)))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid numeric option: {exc}") from exc
        return options

    def apply_preset(self) -> None:
        if self.preset == "fast":
            self.sample_fps = min(self.sample_fps, 1.0)
            self.max_frames = min(self.max_frames, 900)
        elif self.preset == "deep":
            self.sample_fps = max(self.sample_fps, 4.0)
            self.max_frames = max(self.max_frames, 5000)


@dataclass
class AnalysisResult:
    video_path: str
    started_at_utc: str
    finished_at_utc: str
    file_sha256: str
    file_size_bytes: int
    duration_s: float
    tamper_probability: float
    label: DecisionLabel
    confidence: float
    checks: list[CheckResult] = field(default_factory=list)
    suspicious_segments: list[SegmentEvidence] = field(default_factory=list)
    explanation: list[str] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)
    debug: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "video_path": self.video_path,
            "started_at_utc": self.started_at_utc,
            "finished_at_utc": self.finished_at_utc,
            "file_sha256": self.file_sha256,
            "file_size_bytes": self.file_size_bytes,
            "duration_s": round(self.duration_s, 3),
            "tamper_probability": round(self.tamper_probability, 4),
            "label": self.label,
            "confidence": round(self.confidence, 4),
            "checks": [check.to_dict() for check in self.checks],
            "suspicious_segments": [segment.to_dict() for segment in self.suspicious_segments],
            "explanation": self.explanation,
            "options": self.options,
            "debug": self.debug,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_for_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def file_size(path: str) -> int:
    return os.path.getsize(path)
