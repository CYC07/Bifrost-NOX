"""multipart/form-data part extraction for the gateway.

An uploaded PDF/DOCX/image arrives inside a multipart body that starts with `--boundary`, so the
whole body sniffs as text and the file never reaches the document/image services. The extractor
returns the file parts so each can be sniffed on its own. It must never raise: any parse problem
yields [] and the caller falls back to whole-body analysis (fail open).
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.multipart import extract_file_parts  # noqa: E402

PDF = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 40


def body(parts, boundary="XyZ123"):
    out = b""
    for name, filename, ctype, data in parts:
        out += f"--{boundary}\r\n".encode()
        disp = f'Content-Disposition: form-data; name="{name}"'
        if filename is not None:
            disp += f'; filename="{filename}"'
        out += disp.encode() + b"\r\n"
        if ctype:
            out += f"Content-Type: {ctype}\r\n".encode()
        out += b"\r\n" + data + b"\r\n"
    return out + f"--{boundary}--\r\n".encode()


CT = "multipart/form-data; boundary=XyZ123"


def test_extracts_file_parts_with_names_and_exact_bytes():
    b = body([("title", None, None, b"hello"), ("doc", "a.pdf", "application/pdf", PDF),
              ("img", "p.png", "image/png", PNG)])
    parts = extract_file_parts(CT, b)
    assert [(p.filename, p.data) for p in parts] == [("a.pdf", PDF), ("p.png", PNG)]


def test_plain_form_fields_are_not_returned():
    assert extract_file_parts(CT, body([("a", None, None, b"1"), ("b", None, None, b"2")])) == []


def test_binary_data_containing_crlf_and_boundary_like_text_is_preserved():
    data = b"%PDF-1.4\r\n--XyZ12\r\nnot a boundary\r\n" + bytes(range(256))
    parts = extract_file_parts(CT, body([("f", "x.pdf", "application/pdf", data)]))
    assert len(parts) == 1 and parts[0].data == data


def test_quoted_boundary_and_case_insensitive_header():
    b = body([("f", "x.pdf", "application/pdf", PDF)], boundary="a b=c")
    parts = extract_file_parts('MULTIPART/Form-Data; Boundary="a b=c"', b)
    assert len(parts) == 1 and parts[0].data == PDF


@pytest.mark.parametrize("ct", ["", None, "application/json", "multipart/form-data", "multipart/form-data; boundary="])
def test_non_multipart_or_missing_boundary_returns_empty(ct):
    assert extract_file_parts(ct, body([("f", "x.pdf", None, PDF)])) == []


@pytest.mark.parametrize("junk", [b"", b"--XyZ123", b"--XyZ123\r\n", b"\x00\xff" * 50,
                                  b"--XyZ123\r\nContent-Disposition: form-data; name=f; filename=a\r\n\r\ntruncated"])
def test_malformed_bodies_never_raise(junk):
    assert isinstance(extract_file_parts(CT, junk), list)


def test_part_and_size_limits_are_enforced():
    many = body([(f"f{i}", f"{i}.pdf", "application/pdf", PDF) for i in range(40)])
    assert len(extract_file_parts(CT, many, max_parts=16)) == 16
    big = body([("f", "big.pdf", "application/pdf", PDF + b"A" * 5000)])
    assert extract_file_parts(CT, big, max_part_bytes=1000) == []


def test_filename_missing_but_file_content_type_still_counts_as_file():
    b = body([("f", None, "application/pdf", PDF)])
    # a part with a binary content-type but no filename is still an upload
    parts = extract_file_parts(CT, b)
    assert len(parts) == 1 and parts[0].data == PDF
