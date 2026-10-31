"""A PDF with junk before the header must still be recognised as a document.

PDF readers (and our own YARA/structure analyzers) accept `%PDF-x.y` anywhere in the first 1 KiB.
The sniffer only accepted it at offset 0, so prefixing a malicious PDF with a few bytes of junk
(a known evasion; 6 of 24 real corkami test PDFs do it) kept it away from the document service.
"""
import asyncio
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "gateway"))
sys.path.insert(0, ROOT)
from common.utils import FileSniffer  # noqa: E402
import proxy as gw  # noqa: E402

BODY = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< >>\n%%EOF\n" * 3


@pytest.mark.parametrize("prefix", [b"", b"junk\n", b"\x00\x01\x02", b"A" * 500, b"A" * 1000, b"\xef\xbb\xbf", b"\r\n\r\n# comment\n"])
def test_pdf_header_within_the_first_kib_is_a_document(prefix):
    assert FileSniffer.get_true_file_type(prefix + BODY) == "document"


def test_header_beyond_the_first_kib_is_not_a_document():
    assert FileSniffer.get_true_file_type(b"A" * 1100 + BODY) != "document"


@pytest.mark.parametrize("header", [
    b"%PDF-1.\n1 0 obj<<>>endobj",            # truncated version (real corkami PoC)
    b"%PDF-\x00obj<<>>trailer<<>>",           # no version at all
    b"% some comment text first\r\n%PDF-1.7\n1 0 obj<<>>endobj",
    b"% x\n%PDF-1.\n1 0 obj",
])
def test_sloppy_or_commented_headers_that_readers_accept_are_documents(header):
    assert FileSniffer.get_true_file_type(header) == "document"


def test_existing_behaviour_is_kept_for_a_pdf_marker_at_offset_zero():
    assert FileSniffer.get_true_file_type(b"%PDF\n1 0 obj<<>>endobj") == "document"


@pytest.mark.parametrize("text", [
    b"The %PDF format is described elsewhere",          # marker not at offset 0 and no hyphen
    b"hello world, nothing to see",
    b'{"note": "a PDF file"}',
    b"<html><body>PDF documents start with a header</body></html>",
])
def test_text_that_merely_mentions_pdf_is_not_a_document(text):
    assert FileSniffer.get_true_file_type(text) == "text"


def test_other_magics_still_win_over_a_pdf_marker_in_their_data():
    png = b"\x89PNG\r\n\x1a\n" + b"%PDF-1.4" + b"\x00" * 20
    zipf = b"PK\x03\x04" + b"%PDF-1.4" + b"\x00" * 20
    mz = b"MZ\x90\x00" + b"%PDF-1.4" + b"\x00" * 20
    assert FileSniffer.get_true_file_type(png) == "image"
    assert FileSniffer.get_true_file_type(zipf) == "document"
    assert FileSniffer.get_true_file_type(mz) == "executable"


def test_junk_prefixed_pdf_is_routed_to_the_document_service():
    calls = []

    async def spy(c_type, payload, direction, *a, **k):
        calls.append(c_type)
        return {"status": "allow", "reason": ""}

    i = gw.IDPInspector()
    i.send_to_ai = spy
    asyncio.run(i.inspect_full({"content-type": "application/pdf"}, b"junk\n" + BODY, "inbound", True, src_ip="a",
                               dst_ip="x", dst_port=443, host="x.example", method="GET", path="/f",
                               server_name="x.example", dest_ip="203.0.113.9"))
    assert calls == ["document"]


def test_multipart_bodies_are_not_mistaken_for_a_pdf_because_a_part_is_one():
    """The lenient header search must not fire on the multipart envelope itself."""
    body = (b"--B0UND\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.pdf\"\r\n"
            b"Content-Type: application/pdf\r\n\r\n" + BODY + b"\r\n--B0UND--\r\n")
    assert FileSniffer.get_true_file_type(body, lenient_pdf=False) == "text"
    # ... while the part itself, sniffed on its own, is a document (even with junk in front)
    assert FileSniffer.get_true_file_type(b"junk" + BODY) == "document"


def test_gateway_does_not_route_a_multipart_envelope_as_a_document():
    calls = []

    async def spy(c_type, payload, direction, *a, **k):
        calls.append(c_type)
        return {"status": "allow", "reason": ""}

    body = (b"--B0UND\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n"
            b"--B0UND\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.pdf\"\r\n"
            b"Content-Type: application/pdf\r\n\r\n" + BODY + b"\r\n--B0UND--\r\n")
    i = gw.IDPInspector()
    i.send_to_ai = spy
    asyncio.run(i.inspect_full({"content-type": "multipart/form-data; boundary=B0UND"}, body, "inbound", True,
                               src_ip="a", dst_ip="x", dst_port=443, host="x.example", method="GET", path="/f",
                               server_name="x.example", dest_ip="203.0.113.9"))
    assert "document" not in calls
