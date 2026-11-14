"""Legacy Office binaries (.doc/.xls/.ppt: OLE2 compound files) are blocked outright.

There is no OLE analyzer (0/18 real macro/exploit samples were detected by the document service)
and legacy binaries are a classic malware carrier, so the gateway blocks them the way it blocks
executables. Only Word/Excel/PowerPoint containers are blocked: other OLE files (MSI, Outlook .msg,
Visio) and the OLE wrapper of *encrypted* modern OOXML are not "old Office binaries" and pass.
"""
import asyncio
import os
import struct
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "gateway"))
sys.path.insert(0, ROOT)
from common.utils import FileSniffer  # noqa: E402
import proxy as gw  # noqa: E402

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def make_ole(*stream_names: str, junk: bytes = b"", header: int = 512) -> bytes:
    """A minimal OLE2-looking blob: magic, zero header, then 128-byte directory entries."""
    out = bytearray(OLE_MAGIC + b"\x00" * (header - len(OLE_MAGIC)))
    for name in ("Root Entry",) + stream_names:
        raw = name.encode("utf-16-le") + b"\x00\x00"
        entry = bytearray(128)
        entry[: len(raw)] = raw
        struct.pack_into("<H", entry, 64, len(raw))
        out += entry
    return bytes(out) + junk


WORD = make_ole("WordDocument", "1Table", "\x05SummaryInformation")
EXCEL = make_ole("Workbook", "\x05SummaryInformation")
EXCEL5 = make_ole("Book")
PPT = make_ole("PowerPoint Document", "Current User")
PPT4 = make_ole("PP40", "Current User")          # PowerPoint 4.0 (Mac/Win 1994): main stream is "PP40"
MSI_LIKE = make_ole("\x05SummaryInformation", "!_StringData", "!_StringPool")
MSG_LIKE = make_ole("__properties_version1.0", "__substg1.0_0037001F")
ENCRYPTED_OOXML = make_ole("EncryptedPackage", "EncryptionInfo")


# --- sniffer -------------------------------------------------------------------------------
@pytest.mark.parametrize("blob", [WORD, EXCEL, EXCEL5, PPT, PPT4])
def test_word_excel_powerpoint_containers_are_legacy_office(blob):
    assert FileSniffer.get_true_file_type(blob) == "legacy_office"
    assert FileSniffer.is_legacy_office(blob)


def test_4096_byte_sector_files_are_recognised_too():
    assert FileSniffer.is_legacy_office(make_ole("WordDocument", header=4096))


@pytest.mark.parametrize("blob", [MSI_LIKE, MSG_LIKE, ENCRYPTED_OOXML, make_ole()])
def test_other_ole_containers_are_not_legacy_office(blob):
    assert not FileSniffer.is_legacy_office(blob)
    assert FileSniffer.get_true_file_type(blob) == "binary_unknown"


def test_utf16_name_without_the_ole_magic_is_not_enough():
    stray = b"\x00" * 512 + ("WordDocument".encode("utf-16-le") + b"\x00\x00").ljust(128, b"\x00")
    assert not FileSniffer.is_legacy_office(stray)


def test_name_at_a_misaligned_offset_is_not_a_directory_entry():
    """A document that merely *quotes* the stream name inside its data must not count."""
    name = "WordDocument".encode("utf-16-le") + b"\x00\x00"
    blob = OLE_MAGIC + b"\x00" * 504 + b"\x00" * 37 + name        # not on a 128-byte slot
    assert not FileSniffer.is_legacy_office(blob)


def test_truncated_or_tiny_inputs_never_raise():
    for b in (b"", OLE_MAGIC, OLE_MAGIC + b"\x00" * 10, b"\xd0\xcf\x11"):
        assert FileSniffer.is_legacy_office(b) is False


def test_existing_types_are_unchanged():
    assert FileSniffer.get_true_file_type(b"%PDF-1.4\n") == "document"
    assert FileSniffer.get_true_file_type(b"PK\x03\x04" + b"\x00" * 20) == "document"
    assert FileSniffer.get_true_file_type(b"MZ" + b"\x00" * 20) == "executable"
    assert FileSniffer.get_true_file_type(b"hello world") == "text"


# --- gateway -------------------------------------------------------------------------------
class Spy:
    def __init__(self):
        self.calls = []

    async def __call__(self, c_type, payload, direction, *a, **k):
        self.calls.append(c_type)
        return {"status": "allow", "reason": "spy"}


def run(body, direction="inbound", host="files.example", headers=None, **kw):
    i = gw.IDPInspector()
    spy = Spy()
    i.send_to_ai = spy
    v = asyncio.run(i.inspect_full(headers or {"content-type": "application/octet-stream"}, body, direction, True,
                                   src_ip="a", dst_ip=host, dst_port=443, host=host, method="GET", path="/f",
                                   server_name=host, dest_ip="203.0.113.9", **kw))
    return v, spy


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.delenv("LEGACY_OFFICE_POLICY", raising=False)
    monkeypatch.delenv("DOC_SCAN_MODE", raising=False)


@pytest.mark.parametrize("blob", [WORD, EXCEL, PPT])
@pytest.mark.parametrize("direction", ["inbound", "outbound"])
def test_legacy_office_is_blocked_in_both_directions_without_analysis(blob, direction):
    v, spy = run(blob, direction)
    assert v == "block" and spy.calls == []


def test_non_office_ole_and_encrypted_ooxml_are_not_blocked():
    for blob in (MSI_LIKE, MSG_LIKE, ENCRYPTED_OOXML):
        assert run(blob)[0] == "allow"


def test_policy_allow_disables_the_block(monkeypatch):
    monkeypatch.setenv("LEGACY_OFFICE_POLICY", "allow")
    assert run(WORD)[0] == "allow"


def test_policy_block_is_the_default_and_explicit_value_works(monkeypatch):
    monkeypatch.setenv("LEGACY_OFFICE_POLICY", "block")
    assert run(WORD)[0] == "block"


def test_pdf_and_ooxml_routing_is_unchanged():
    v, spy = run(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n" * 3)
    assert v == "allow" and spy.calls == ["document"]
    v, spy = run(b"PK\x03\x04" + b"\x14\x00" + b"\x00" * 100)
    assert v == "allow" and spy.calls == ["document"]


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


def test_uploading_a_legacy_office_file_is_blocked():
    body = mp([("note", None, None, b"hello"), ("f", "report.doc", "application/msword", WORD)])
    v, spy = run(body, "outbound", headers=MPH)
    assert v == "block"


def test_uploading_a_non_office_ole_part_is_allowed():
    body = mp([("f", "setup.msi", "application/octet-stream", MSI_LIKE)])
    assert run(body, "outbound", headers=MPH)[0] == "allow"


def test_verified_microsoft_hosts_are_still_exempt(tmp_path, monkeypatch):
    import json
    from common import ip_ranges
    r = tmp_path / "r.json"
    r.write_text(json.dumps({"ranges": ["203.0.113.0/24"]}))
    monkeypatch.setattr(ip_ranges, "_PATH", str(r))
    ip_ranges._reset_cache()
    v, spy = run(WORD, host="download.microsoft.com")
    assert v == "allow" and spy.calls == []


# --- optional: the real samples (local corpora are not in the repo) ------------------------
CORPUS = os.environ.get("OLE_CORPUS_DIR", "")


@pytest.mark.skipif(not CORPUS or not os.path.isdir(CORPUS), reason="set OLE_CORPUS_DIR to a dir of real .doc/.xls/.ppt")
def test_real_legacy_office_samples_are_all_recognised():
    exts = (".doc", ".dot", ".xls", ".xlt", ".xla", ".ppt", ".pps", ".pot")
    files = [f for f in sorted(os.listdir(CORPUS)) if f.lower().endswith(exts)]
    assert files, "corpus has no legacy Office files"
    missed = [f for f in files if not FileSniffer.is_legacy_office(open(os.path.join(CORPUS, f), "rb").read())]
    assert missed == [], missed
