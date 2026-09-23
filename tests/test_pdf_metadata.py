from __future__ import annotations

import subprocess

import pytest

from quevidkit.pdf_metadata import PdfMetadataError, extract_pdf_metadata
from quevidkit.webapp import _looks_like_pdf


@pytest.fixture
def sample_pdf(tmp_path):
    path = str(tmp_path / "sample.pdf")
    subprocess.run(
        [
            "python3",
            "-c",
            (
                "from pypdf import PdfWriter; "
                "w = PdfWriter(); w.add_blank_page(width=200, height=300); "
                "w.add_metadata({'/Title': 'Test Doc', '/Author': 'quevidkit'}); "
                f"w.write('{path}')"
            ),
        ],
        check=True,
    )
    return path


def test_looks_like_pdf_accepts_real_header(sample_pdf):
    with open(sample_pdf, "rb") as handle:
        head = handle.read(64)
    assert _looks_like_pdf(head)


def test_looks_like_pdf_rejects_non_pdf():
    assert not _looks_like_pdf(b"this is definitely not a pdf file header")


def test_extract_pdf_metadata_returns_document_info(sample_pdf):
    metadata = extract_pdf_metadata(sample_pdf)
    assert metadata["page_count"] == 1
    assert metadata["is_encrypted"] is False
    assert metadata["document_info"]["title"] == "Test Doc"
    assert metadata["document_info"]["author"] == "quevidkit"
    assert metadata["page_size"]["width_pt"] == pytest.approx(200.0)


def test_extract_pdf_metadata_raises_on_garbage(tmp_path):
    bad_path = tmp_path / "not_a_pdf.pdf"
    bad_path.write_bytes(b"%PDF-1.4\nnot actually valid pdf content")
    with pytest.raises(PdfMetadataError):
        extract_pdf_metadata(str(bad_path))
