"""Leaf certs minted by the MITM CA must tolerate a client whose clock is slow
(VMs / fresh devices): notBefore is backdated so a just-minted leaf is already valid."""
import datetime
import os
import sys

from cryptography import x509

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "gateway")))
from cert_utils import CertificateAuthority  # noqa: E402


def _leaf(tmp_path, host="example.test"):
    ca = CertificateAuthority(cert_dir=str(tmp_path))
    ret = ca.get_certificate_for_host(host)
    cert_path = ret[0] if isinstance(ret, (tuple, list)) else ret
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def test_leaf_cert_is_backdated(tmp_path):
    cert = _leaf(tmp_path)
    now = datetime.datetime.utcnow()
    assert cert.not_valid_before.replace(tzinfo=None) <= now - datetime.timedelta(hours=23)


def test_leaf_cert_valid_for_client_clock_eight_hours_behind(tmp_path):
    cert = _leaf(tmp_path)
    slow_clock = datetime.datetime.utcnow() - datetime.timedelta(hours=8, minutes=18)
    assert cert.not_valid_before.replace(tzinfo=None) <= slow_clock <= cert.not_valid_after.replace(tzinfo=None)
