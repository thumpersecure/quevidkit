from __future__ import annotations

import os
import struct
from typing import Any

from .models import CheckResult
from .scoring import clamp01


# ── Content-credential / provenance manifest detection ───────────────────────

_JUMBF_MARKERS = (b"jumb", b"c2pa")
_XMP_MARKERS = (b"<?xpacket", b"http://ns.adobe.com/xap/")
_UUID_MARKER = b"urn:uuid"

_XMP_EDIT_TOOL_MARKERS = (
    b"adobe premiere",
    b"premiere pro",
    b"final cut",
    b"capcut",
    b"davinci resolve",
    b"davinci",
    b"adobe photoshop",
    b"after effects",
)

_SCAN_CAP_BYTES = 50 * 1024 * 1024  # 50MB cap per read region


def _read_scan_window(path: str, cap_bytes: int = _SCAN_CAP_BYTES) -> bytes:
    """Read up to cap_bytes from the start, plus a tail window for small-cap files.

    Provenance manifests (C2PA/JUMBF boxes, XMP packets) are typically embedded
    near the start or end of a container, so scanning head+tail is a reasonable
    heuristic without reading arbitrarily large files into memory.
    """
    size = os.path.getsize(path)
    if size <= cap_bytes:
        with open(path, "rb") as handle:
            return handle.read()

    head_bytes = cap_bytes // 2
    tail_bytes = cap_bytes - head_bytes
    with open(path, "rb") as handle:
        head = handle.read(head_bytes)
        handle.seek(max(0, size - tail_bytes))
        tail = handle.read(tail_bytes)
    return head + tail


def provenance_manifest_checks(path: str, basic_probe: dict[str, Any]) -> CheckResult:
    """Detect C2PA/JUMBF content-credential manifests and XMP metadata in the file.

    Presence of a C2PA/JUMBF manifest is a positive signal (provenance credentials
    exist and could be cryptographically verified externally), not a red flag.
    Presence of XMP edit-history metadata is informational only — legitimately
    edited video routinely carries this. Absence of either is common and, on its
    own, is not evidence of tampering.
    """
    details: dict[str, Any] = {}

    try:
        format_tags = basic_probe.get("format", {}).get("tags", {})
        if not isinstance(format_tags, dict):
            format_tags = {}
    except Exception:
        format_tags = {}

    tag_hits = []
    for key, value in format_tags.items():
        key_l = str(key).lower()
        val_l = str(value).lower() if value is not None else ""
        if "xmp" in key_l or "c2pa" in key_l or "jumb" in key_l:
            tag_hits.append(key)
        elif "xmp" in val_l or "c2pa" in val_l:
            tag_hits.append(key)
    details["format_tag_provenance_hits"] = tag_hits

    if not os.path.isfile(path):
        return CheckResult(
            name="provenance_manifest",
            category="metadata",
            score=0.0,
            confidence=0.05,
            summary="File not accessible for provenance manifest scan.",
            details=details,
        )

    try:
        blob = _read_scan_window(path)
    except OSError as exc:
        return CheckResult(
            name="provenance_manifest",
            category="metadata",
            score=0.0,
            confidence=0.05,
            summary=f"Could not read file for provenance scan: {exc}",
            details=details,
        )

    blob_lower = blob.lower()

    jumbf_found = any(marker in blob_lower for marker in _JUMBF_MARKERS)
    uuid_urn_found = _UUID_MARKER in blob_lower
    xmp_packet_found = any(marker in blob_lower for marker in _XMP_MARKERS)
    xmp_edit_tool_hits = sorted(
        {marker.decode("ascii") for marker in _XMP_EDIT_TOOL_MARKERS if marker in blob_lower}
    )

    details["jumbf_or_c2pa_signature_found"] = jumbf_found
    details["uuid_urn_marker_found"] = uuid_urn_found
    details["xmp_packet_found"] = xmp_packet_found
    details["xmp_edit_tool_markers"] = xmp_edit_tool_hits
    details["scan_bytes"] = len(blob)

    has_c2pa_signal = jumbf_found or (uuid_urn_found and xmp_packet_found)
    has_xmp_signal = xmp_packet_found or bool(tag_hits)

    if has_c2pa_signal:
        score = 0.05
        summary = (
            "Content-credential (C2PA/JUMBF) manifest signature detected — this is a "
            "positive provenance signal, not a tampering indicator. Verify the manifest "
            "cryptographically with a dedicated C2PA validator for authoritative results."
        )
        confidence = 0.5
    elif has_xmp_signal:
        score = 0.12
        summary = (
            "XMP metadata present"
            + (f" with editing-tool markers ({', '.join(xmp_edit_tool_hits)})" if xmp_edit_tool_hits else "")
            + ". This is informational: embedded edit history is normal for legitimately "
            "edited video and is not itself suspicious."
        )
        confidence = 0.4
    else:
        score = 0.08
        summary = (
            "No C2PA/JUMBF or XMP provenance metadata found. Absence of provenance data "
            "is common for ordinary camera and platform exports and is NOT itself "
            "evidence of tampering — most authentic video carries no such manifest."
        )
        confidence = 0.3

    return CheckResult(
        name="provenance_manifest",
        category="metadata",
        score=clamp01(score),
        confidence=clamp01(confidence),
        summary=summary,
        details=details,
        segments=[],
    )


# ── Container box-level editing-trace scan ────────────────────────────────────

_ISO_BMFF_TOP_BOXES = {
    b"ftyp", b"moov", b"mdat", b"free", b"skip", b"uuid", b"wide",
    b"pnot", b"moof", b"mfra", b"meta", b"meco", b"styp", b"sidx",
    b"prft",
}

# Rough expectation: single-pass encoders/exporters typically emit a handful of
# top-level boxes (ftyp, moov, mdat, maybe free/wide). Many more than this
# suggests a multi-tool / multi-pass pipeline (fragmented mp4, remuxing, etc.)
_TYPICAL_MAX_TOP_BOXES = 8

_TYPICAL_AUDIO_CODEC_BY_BRAND = {
    b"mp42": {"aac"},
    b"isom": {"aac"},
    b"m4a ": {"aac", "alac"},
    b"qt  ": {"aac", "pcm_s16le", "alac"},
    b"3gp4": {"aac", "amr_nb"},
    b"3gp5": {"aac", "amr_nb"},
    b"mp41": {"aac"},
}


def _walk_top_level_boxes(handle, file_size: int, max_boxes: int = 4096) -> list[dict[str, Any]]:
    """Walk top-level ISO-BMFF boxes: 4-byte size + 4-byte type, optional 64-bit size."""
    boxes: list[dict[str, Any]] = []
    offset = 0
    handle.seek(0)
    count = 0
    while offset < file_size and count < max_boxes:
        handle.seek(offset)
        header = handle.read(8)
        if len(header) < 8:
            break
        size32, box_type = struct.unpack(">I4s", header)
        header_size = 8
        if size32 == 1:
            ext = handle.read(8)
            if len(ext) < 8:
                break
            (size64,) = struct.unpack(">Q", ext)
            box_size = size64
            header_size = 16
        elif size32 == 0:
            box_size = file_size - offset
        else:
            box_size = size32

        if box_size < header_size:
            # Malformed box; bail out rather than looping forever.
            break

        boxes.append({"type": box_type, "offset": offset, "size": box_size})
        offset += box_size
        count += 1
    return boxes


def container_edit_trace_checks(path: str, basic_probe: dict[str, Any]) -> CheckResult:
    """Walk top-level ISO-BMFF boxes looking for editor-left structural traces.

    This goes beyond the moov/mdat-ordering and software-tag checks already done
    elsewhere in the pipeline (metadata_codec_checks, frame_structure_checks) by
    directly parsing the top-level box layout from raw file bytes: duplicate/
    oversized free-or-skip boxes (space left behind by in-place edits), vendor
    'uuid' extension boxes, unusual box-count fragmentation, and a low-confidence
    audio-codec-vs-container-brand heuristic.
    """
    details: dict[str, Any] = {}

    if not os.path.isfile(path):
        return CheckResult(
            name="container_edit_trace",
            category="metadata",
            score=0.0,
            confidence=0.05,
            summary="File not accessible for container box scan.",
            details=details,
        )

    format_name = str(basic_probe.get("format", {}).get("format_name", "")).lower()
    is_isobmff_container = any(
        token in format_name for token in ("mp4", "mov", "m4a", "3gp", "3g2", "qt")
    )

    try:
        size_bytes = os.path.getsize(path)
        with open(path, "rb") as handle:
            ftyp_header = handle.read(12)
    except OSError as exc:
        return CheckResult(
            name="container_edit_trace",
            category="metadata",
            score=0.0,
            confidence=0.05,
            summary=f"Could not read file for container box scan: {exc}",
            details=details,
        )

    looks_like_isobmff = len(ftyp_header) >= 8 and ftyp_header[4:8] in (b"ftyp", b"styp", b"free", b"moov", b"mdat", b"skip", b"wide", b"uuid")

    if not (is_isobmff_container or looks_like_isobmff):
        return CheckResult(
            name="container_edit_trace",
            category="metadata",
            score=0.0,
            confidence=0.15,
            summary=(
                f"Container format '{format_name or 'unknown'}' is not ISO-BMFF "
                "(MP4/MOV) — box-level editing-trace scan does not apply."
            ),
            details=details,
        )

    try:
        with open(path, "rb") as handle:
            boxes = _walk_top_level_boxes(handle, size_bytes)
    except (OSError, struct.error) as exc:
        return CheckResult(
            name="container_edit_trace",
            category="metadata",
            score=0.0,
            confidence=0.1,
            summary=f"Container box parsing failed: {exc}",
            details=details,
        )

    if not boxes:
        return CheckResult(
            name="container_edit_trace",
            category="metadata",
            score=0.0,
            confidence=0.1,
            summary="No parseable top-level boxes found; file may be malformed or non-ISO-BMFF.",
            details=details,
        )

    box_types = [b["type"] for b in boxes]
    recognized = sum(1 for t in box_types if t in _ISO_BMFF_TOP_BOXES)
    recognized_ratio = recognized / len(boxes)
    details["top_level_box_count"] = len(boxes)
    details["top_level_box_types"] = [t.decode("ascii", errors="replace") for t in box_types]
    details["recognized_box_ratio"] = round(recognized_ratio, 3)

    if recognized_ratio < 0.5:
        return CheckResult(
            name="container_edit_trace",
            category="metadata",
            score=0.0,
            confidence=0.15,
            summary=(
                "Top-level structure does not resemble standard ISO-BMFF box "
                "layout; skipping editing-trace heuristics for this container."
            ),
            details=details,
        )

    findings: list[tuple[str, float]] = []

    free_skip = [b for b in boxes if b["type"] in (b"free", b"skip")]
    free_skip_total = sum(b["size"] for b in free_skip)
    details["free_skip_box_count"] = len(free_skip)
    details["free_skip_total_bytes"] = free_skip_total
    if len(free_skip) >= 2 and free_skip_total > 512 * 1024:
        ratio = free_skip_total / max(size_bytes, 1)
        findings.append((
            f"{len(free_skip)} free/skip boxes totaling {free_skip_total} bytes "
            f"({ratio:.1%} of file) — consistent with space left by in-place editing",
            clamp01(0.2 + ratio * 2.0),
        ))

    uuid_boxes = [b for b in boxes if b["type"] == b"uuid"]
    details["uuid_box_count"] = len(uuid_boxes)
    if uuid_boxes:
        findings.append((
            f"{len(uuid_boxes)} vendor-specific 'uuid' extension box(es) present",
            0.15,
        ))

    moov_boxes = [b for b in boxes if b["type"] == b"moov"]
    mdat_boxes = [b for b in boxes if b["type"] == b"mdat"]
    if moov_boxes and mdat_boxes:
        moov_before_mdat = moov_boxes[0]["offset"] < mdat_boxes[0]["offset"]
        details["moov_before_mdat"] = moov_before_mdat
        # moov-after-mdat is normal for many single-pass camera/phone encoders
        # (moov is finalized after capture) and is NOT inherently anomalous on
        # its own — this is a weak, informational-only sub-signal.
        if not moov_before_mdat:
            details["moov_position_note"] = (
                "moov follows mdat; common for streaming-optimized or "
                "single-pass camera output, not inherently suspicious"
            )

    if len(boxes) > _TYPICAL_MAX_TOP_BOXES:
        findings.append((
            f"{len(boxes)} top-level boxes present (typical single-pass output has "
            f"~{_TYPICAL_MAX_TOP_BOXES} or fewer) — may indicate a multi-tool/multi-pass pipeline",
            clamp01((len(boxes) - _TYPICAL_MAX_TOP_BOXES) / 20.0),
        ))

    # Weak audio-codec-vs-major_brand heuristic.
    major_brand = b""
    for b in boxes:
        if b["type"] == b"ftyp":
            try:
                with open(path, "rb") as handle:
                    handle.seek(b["offset"] + 8)
                    major_brand = handle.read(4)
            except OSError:
                major_brand = b""
            break

    audio_codec = None
    for stream in basic_probe.get("streams", []):
        if stream.get("codec_type") == "audio":
            audio_codec = stream.get("codec_name")
            break

    if major_brand:
        details["major_brand"] = major_brand.decode("ascii", errors="replace")
    if audio_codec:
        details["audio_codec"] = audio_codec

    expected_codecs = _TYPICAL_AUDIO_CODEC_BY_BRAND.get(major_brand)
    if expected_codecs and audio_codec and audio_codec not in expected_codecs:
        findings.append((
            f"audio codec '{audio_codec}' is atypical for major_brand "
            f"'{major_brand.decode('ascii', errors='replace')}' (weak, low-confidence heuristic)",
            0.1,
        ))

    if not findings:
        score = 0.05
        summary = "Container box structure shows no notable editing-trace anomalies."
    else:
        score = clamp01(sum(w for _, w in findings) / max(len(findings), 1))
        summary = "; ".join(f for f, _ in findings[:3])

    confidence = clamp01(0.35 + min(len(boxes), 20) / 60.0)

    return CheckResult(
        name="container_edit_trace",
        category="metadata",
        score=score,
        confidence=confidence,
        summary=summary,
        details={**details, "findings": findings},
        segments=[],
    )
