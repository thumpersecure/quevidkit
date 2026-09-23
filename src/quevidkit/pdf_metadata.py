from __future__ import annotations

from typing import Any

from pypdf import PdfReader
from pypdf.errors import PdfReadError


class PdfMetadataError(RuntimeError):
    """Raised when a PDF can't be parsed for metadata."""


def _iso_from_pdf_date(value: str | None) -> str | None:
    """pypdf already normalizes D:YYYYMMDDHHmmSS to ISO where it can; pass through."""
    if not value:
        return None
    return str(value)


def extract_pdf_metadata(path: str) -> dict[str, Any]:
    try:
        reader = PdfReader(path)
    except (PdfReadError, ValueError) as exc:
        raise PdfMetadataError(f"Could not parse PDF: {exc}") from exc

    info = reader.metadata or {}
    xmp = reader.xmp_metadata

    doc_info = {
        "title": info.get("/Title") if info else None,
        "author": info.get("/Author") if info else None,
        "subject": info.get("/Subject") if info else None,
        "keywords": info.get("/Keywords") if info else None,
        "creator": info.get("/Creator") if info else None,
        "producer": info.get("/Producer") if info else None,
        "creation_date": _iso_from_pdf_date(info.get("/CreationDate")) if info else None,
        "modification_date": _iso_from_pdf_date(info.get("/ModDate")) if info else None,
    }

    xmp_data: dict[str, Any] | None = None
    if xmp is not None:
        try:
            xmp_data = {
                "xmp_create_date": getattr(xmp, "xmp_create_date", None),
                "xmp_modify_date": getattr(xmp, "xmp_modify_date", None),
                "xmp_metadata_date": getattr(xmp, "xmp_metadata_date", None),
                "xmp_creator_tool": getattr(xmp, "xmp_creator_tool", None),
                "pdf_producer": getattr(xmp, "pdf_producer", None),
                "dc_title": getattr(xmp, "dc_title", None),
                "dc_creator": getattr(xmp, "dc_creator", None),
            }
        except Exception:
            xmp_data = None

    # A hostile PDF can declare an absurd page count or a page-tree structure
    # that's expensive to walk; cap what we're willing to report/traverse
    # rather than trusting the document's own numbers.
    MAX_REPORTED_PAGES = 1_000_000
    try:
        page_count = len(reader.pages)
        if page_count > MAX_REPORTED_PAGES:
            raise PdfMetadataError(f"PDF declares an implausible page count ({page_count}); refusing to process.")
    except PdfMetadataError:
        raise
    except Exception:
        page_count = None

    first_page = reader.pages[0] if page_count else None
    page_size = None
    if first_page is not None:
        try:
            box = first_page.mediabox
            page_size = {"width_pt": float(box.width), "height_pt": float(box.height)}
        except Exception:
            page_size = None

    return {
        "page_count": page_count,
        "page_size": page_size,
        "is_encrypted": reader.is_encrypted,
        "pdf_version": getattr(reader, "pdf_header", None),
        "document_info": doc_info,
        "xmp_metadata": xmp_data,
        "has_javascript": bool(getattr(reader, "get_fields", None) and _has_js(reader)),
        "attachments": list(getattr(reader, "attachments", {}).keys()) if hasattr(reader, "attachments") else [],
    }


def _has_js(reader: PdfReader) -> bool:
    try:
        root = reader.trailer["/Root"]
        names = root.get("/Names")
        return bool(names and "/JavaScript" in names)
    except Exception:
        return False
