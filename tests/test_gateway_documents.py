"""Gateway routing of documents and uploaded files.

Before: inspect_full sent everything that wasn't an image to the *text* service, so a PDF/ZIP/DOCX
(download or upload) never reached the document service (YARA, structure, metadata).
Executables keep the blanket block (user decision); trusted Microsoft hosts are unchanged.
"""
import asyncio
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "gateway"))
sys.path.insert(0, ROOT)
import proxy as gw  # noqa: E402

PDF = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< >>\n%%EOF\n" * 3
ZIP = b"PK\x03\x04" + b"\x14\x00\x00\x00\x00\x00" + b"\x00" * 100
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
EXE = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 200


class Spy:
    def __init__(self, status="allow"):
        self.calls = []
        self.status = status

    async def __call__(self, c_type, payload, direction, *a, **k):
        self.calls.append((c_type, payload, k))
        return {"status": self.status, "reason": "spy"}


def _insp(spy):
    i = gw.IDPInspector()
    i.send_to_ai = spy
    return i


def run(i, body, headers=None, direction="inbound", host="files.example", **kw):
    return asyncio.run(i.inspect_full(headers or {"content-type": "application/octet-stream"}, body, direction,
                                      True, src_ip="a", dst_ip=host, dst_port=443, host=host, method="GET",
                                      path="/f", server_name=host, dest_ip="203.0.113.9", **kw))


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.delenv("DOC_SCAN_MODE", raising=False)
    monkeypatch.delenv("DOC_SCAN_MAX_BYTES", raising=False)


# --- routing --------------------------------------------------------------------------------
@pytest.mark.parametrize("blob", [PDF, ZIP])
def test_documents_go_to_the_document_service(blob):
    spy = Spy()
    assert run(_insp(spy), blob) == "allow"
    assert [c[0] for c in spy.calls] == ["document"]
    assert spy.calls[0][1] == blob


def test_images_and_text_routing_is_unchanged():
    spy = Spy()
    run(_insp(spy), PNG)
    run(_insp(spy), b"hello world plain text body")
    assert [c[0] for c in spy.calls] == ["image", "text"]


def test_document_block_verdict_is_enforced():
    assert run(_insp(Spy("block")), PDF) == "block"


def test_executables_keep_the_blanket_block_without_analysis():
    spy = Spy()
    assert run(_insp(spy), EXE) == "block"
    assert spy.calls == []


def test_documents_above_the_size_cap_are_allowed_unanalysed(monkeypatch):
    monkeypatch.setenv("DOC_SCAN_MAX_BYTES", "100")
    spy = Spy("block")
    assert run(_insp(spy), PDF + b"x" * 500) == "allow"
    assert spy.calls == []


def test_mode_off_restores_the_legacy_text_route(monkeypatch):
    monkeypatch.setenv("DOC_SCAN_MODE", "off")
    spy = Spy()
    run(_insp(spy), PDF)
    assert [c[0] for c in spy.calls] == ["text"]


def test_trusted_verified_microsoft_hosts_still_skip_everything(tmp_path, monkeypatch):
    import json
    from common import ip_ranges, trusted_domains
    r = tmp_path / "r.json"
    r.write_text(json.dumps({"ranges": ["203.0.113.0/24"]}))
    monkeypatch.setattr(ip_ranges, "_PATH", str(r))
    ip_ranges._reset_cache()
    spy = Spy("block")
    assert run(_insp(spy), PDF, host="dl.delivery.mp.microsoft.com") == "allow"
    assert spy.calls == []


# --- uploads (multipart) --------------------------------------------------------------------
def mp(parts, boundary="B0UND"):
    out = b""
    for name, filename, ctype, data in parts:
        out += f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"".encode()
        if filename:
            out += f'; filename="{filename}"'.encode()
        out += b"\r\n"
        if ctype:
            out += f"Content-Type: {ctype}\r\n".encode()
        out += b"\r\n" + data + b"\r\n"
    return out + f"--{boundary}--\r\n".encode()


MPH = {"content-type": "multipart/form-data; boundary=B0UND"}


def test_uploaded_pdf_and_image_parts_are_analysed_by_the_right_service():
    spy = Spy()
    body = mp([("note", None, None, b"hi"), ("doc", "a.pdf", "application/pdf", PDF),
               ("pic", "p.png", "image/png", PNG)])
    assert run(_insp(spy), body, headers=MPH, direction="outbound") == "allow"
    kinds = [c[0] for c in spy.calls]
    assert "document" in kinds and "image" in kinds
    assert dict((c[0], c[1]) for c in spy.calls)["document"] == PDF


def test_text_only_upload_body_still_gets_whole_body_text_analysis_after_part_routing():
    """Unchanged behaviour: when the body sniffs as text (no NUL in the first KB) the whole
    multipart is still analysed as text (injection/secrets in the other fields)."""
    spy = Spy()
    body = mp([("note", None, None, b"my note"), ("doc", "a.pdf", "application/pdf", PDF)])
    assert run(_insp(spy), body, headers=MPH, direction="outbound") == "allow"
    kinds = [c[0] for c in spy.calls]
    assert kinds.count("document") == 1 and "text" in kinds


def test_a_blocked_upload_part_blocks_the_request():
    class BlockDocs(Spy):
        async def __call__(self, c_type, payload, direction, *a, **k):
            self.calls.append((c_type, payload, k))
            return {"status": "block" if c_type == "document" else "allow", "reason": "yara"}
    body = mp([("doc", "a.pdf", "application/pdf", PDF)])
    assert run(_insp(BlockDocs()), body, headers=MPH, direction="outbound") == "block"


def test_garbage_multipart_falls_back_to_whole_body_analysis():
    spy = Spy()
    assert run(_insp(spy), b"--B0UND\r\nbroken", headers=MPH, direction="outbound") == "allow"
    assert [c[0] for c in spy.calls] == ["text"]


def test_multipart_without_files_is_unchanged():
    spy = Spy()
    run(_insp(spy), mp([("a", None, None, b"1")]), headers=MPH, direction="outbound")
    assert [c[0] for c in spy.calls] == ["text"]


def test_part_analysis_is_skipped_for_inbound_replies():
    spy = Spy()
    run(_insp(spy), mp([("doc", "a.pdf", "application/pdf", PDF)]), headers=MPH, direction="inbound")
    assert "document" not in [c[0] for c in spy.calls]
