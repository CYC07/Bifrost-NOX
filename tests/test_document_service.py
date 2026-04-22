"""Unit tests for document_service models.

Tests are designed to run without LayoutLM weights (DOC_ENABLE_LAYOUTLM unset).
PyMuPDF and yara-python are required; tests skip cleanly if missing.
"""

from __future__ import annotations

import io
import os
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

fitz = pytest.importorskip("fitz")
yara = pytest.importorskip("yara")

from document_service import (  # noqa: E402
    content_model,
    malware_model,
    metadata_model,
    structure_model,
)


# ---------------------------------------------------------------------------
# Fixtures: bytes-only document factories so tests don't touch the filesystem.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module", autouse=True)
def _warm_models():
    structure_model.load_model()
    malware_model.load_rules()
    content_model.load_model()
    yield


def _make_clean_pdf(text: str = "Hello world") -> bytes:
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), text)
    data = doc.tobytes()
    doc.close()
    return data


def _make_pdf_with_openaction_js() -> bytes:
    doc = fitz.open()
    doc.new_page()
    # Inject /OpenAction with embedded /JS at the catalog root.
    xref = doc.pdf_catalog()
    js_xref = doc.get_new_xref()
    doc.update_object(
        js_xref,
        "<< /S /JavaScript /JS (app.alert('hi');) >>",
    )
    doc.xref_set_key(xref, "OpenAction", f"{js_xref} 0 R")
    data = doc.tobytes()
    doc.close()
    return data


def _make_pdf_with_metadata(author: str) -> bytes:
    doc = fitz.open()
    doc.new_page()
    doc.set_metadata({"author": author, "producer": "msfvenom payload generator"})
    data = doc.tobytes()
    doc.close()
    return data


def _make_fake_docx_with_macro() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<w:document xmlns:w='x'/>")
        zf.writestr("word/vbaProject.bin", b"\x00" * 64)
    return buf.getvalue()


def _make_pdf_with_text(body: str) -> bytes:
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), body)
    data = doc.tobytes()
    doc.close()
    return data


# ---------------------------------------------------------------------------
# Structure model
# ---------------------------------------------------------------------------


def test_structure_clean_pdf_passes():
    result = structure_model.analyze(_make_clean_pdf())
    assert result.module == "structure"
    assert result.score < 0.5, result


def test_structure_flags_pdf_with_openaction():
    result = structure_model.analyze(_make_pdf_with_openaction_js())
    assert result.score >= 0.7
    assert any("openaction" in f.lower() or "javascript" in f.lower() for f in result.findings)


def test_structure_flags_docx_with_vba_macro():
    result = structure_model.analyze(_make_fake_docx_with_macro())
    assert result.score >= 0.7
    assert any("vba_project" in f for f in result.findings)


# ---------------------------------------------------------------------------
# Malware model
# ---------------------------------------------------------------------------


EICAR = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


def test_malware_eicar_match():
    result = malware_model.analyze(EICAR)
    assert result.score >= 0.9
    assert any("EICAR" in f for f in result.findings)


def test_malware_macro_rule_match():
    result = malware_model.analyze(_make_fake_docx_with_macro())
    assert result.score >= 0.9
    assert any("VBA" in f or "Macro" in f for f in result.findings)


def test_malware_clean_pdf_no_match():
    result = malware_model.analyze(_make_clean_pdf())
    assert result.score == 0.0


# ---------------------------------------------------------------------------
# Metadata model
# ---------------------------------------------------------------------------


def test_metadata_detects_windows_path_leak():
    pdf = _make_pdf_with_metadata(author="C:\\Users\\victim\\Desktop\\secret.docx")
    result = metadata_model.analyze(pdf)
    assert result.score > 0.0
    joined = " ".join(result.findings)
    assert "Local path leak" in joined or "Suspicious producer" in joined


def test_metadata_clean_pdf_low_score():
    result = metadata_model.analyze(_make_clean_pdf())
    assert result.score <= 0.3


# ---------------------------------------------------------------------------
# Content model (fallback path — LayoutLM disabled)
# ---------------------------------------------------------------------------


def test_content_fallback_keyword_balance_sheet(monkeypatch):
    monkeypatch.delenv("DOC_ENABLE_LAYOUTLM", raising=False)
    pdf = _make_pdf_with_text("INTERNAL FINANCIAL BALANCE SHEET Q3 quarterly revenue")
    result = content_model.analyze(pdf)
    assert result.score >= 0.5
    assert any("balance sheet" in f.lower() for f in result.findings)


def test_content_clean_pdf_safe():
    pdf = _make_pdf_with_text("Hello world this is a public terms of service")
    result = content_model.analyze(pdf)
    assert result.score < 0.5
