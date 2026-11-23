"""get_certificate_for_host() must only ever write inside its certificate directory.

The host comes from the TLS SNI the client sends, so it is attacker controlled. It was joined straight
into a file path (`<cert_dir>/<host>.crt`), so an SNI such as `/root/x` made a root-run proxy write
`/root/x.key` and `/root/x.crt`. A Python client can send exactly that (checked with ssl.MemoryBIO).
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "gateway")))
from cert_utils import CertificateAuthority, is_valid_cert_host  # noqa: E402


@pytest.fixture()
def ca(tmp_path):
    return CertificateAuthority(cert_dir=str(tmp_path / "certs"))


@pytest.mark.parametrize("name", [
    "example.com", "a-b.c_d.example.org", "54.172.45.38", "xn--bcher-kva.example", "UPPER.Example.COM", "localhost",
])
def test_ordinary_names_are_accepted(ca, name):
    cert, key = ca.get_certificate_for_host(name)
    assert os.path.dirname(cert) == ca.cert_dir and os.path.exists(cert) and os.path.exists(key)


@pytest.mark.parametrize("name", [
    "/tmp/pwn", "/etc/ssl/certs/x", "../x", "..", "a/b", "a\\b", "x\x00y", "", " ", ".hidden", "-lead.example",
    "trail.", "a" * 254, "a" * 64 + ".example.com", "sp ace.example", "semi;colon.example", "new\nline.example", "example.com\n",
])
def test_hostile_names_are_rejected_and_write_nothing(ca, tmp_path, name):
    before = set(os.listdir(ca.cert_dir))
    assert not is_valid_cert_host(name)
    with pytest.raises(ValueError):
        ca.get_certificate_for_host(name)
    assert set(os.listdir(ca.cert_dir)) == before          # nothing created inside...
    assert not any(p.name.startswith("pwn") for p in tmp_path.iterdir())   # ...or next to it


def test_absolute_path_name_cannot_escape_the_cert_dir(ca, tmp_path):
    target = tmp_path / "outside" / "pwned"
    os.makedirs(target.parent)
    with pytest.raises(ValueError):
        ca.get_certificate_for_host(str(target))
    assert os.listdir(target.parent) == []


def test_non_string_is_rejected(ca):
    for bad in (None, 123, b"example.com"):
        assert not is_valid_cert_host(bad)
        with pytest.raises(ValueError):
            ca.get_certificate_for_host(bad)
