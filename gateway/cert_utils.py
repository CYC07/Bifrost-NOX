import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import logging

logger = logging.getLogger("cert_utils")

class CertificateAuthority:
    def __init__(self, cert_dir="gateway/certs"):
        self.cert_dir = cert_dir
        if not os.path.exists(self.cert_dir):
            os.makedirs(self.cert_dir)
            
        self.ca_key_path = os.path.join(self.cert_dir, "ca.key")
        self.ca_cert_path = os.path.join(self.cert_dir, "ca.crt")
        
        self.ca_key = None
        self.ca_cert = None
        
        self.load_or_create_ca()

    def load_or_create_ca(self):
        """Load existing CA or create a new one if it doesn't exist."""
        if os.path.exists(self.ca_key_path) and os.path.exists(self.ca_cert_path):
            logger.info("Loading existing CA...")
            try:
                with open(self.ca_key_path, "rb") as f:
                    self.ca_key = serialization.load_pem_private_key(f.read(), password=None)
                with open(self.ca_cert_path, "rb") as f:
                    self.ca_cert = x509.load_pem_x509_certificate(f.read())
            except Exception as e:
                logger.error(f"Failed to load CA, regenerating: {e}")
                self.create_ca()
        else:
            logger.info("No CA found, creating new one...")
            self.create_ca()

    def create_ca(self):
        """Generate a new Root CA."""
        self.ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"AI Firewall Local CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"AI Firewall Root CA"),
        ])

        self.ca_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.ca_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365*10)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(self.ca_key, hashes.SHA256())

        # Save CA
        with open(self.ca_key_path, "wb") as f:
            f.write(self.ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        
        with open(self.ca_cert_path, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))
            
        logger.info(f"CA Generated at {self.cert_dir}")

    def get_certificate_for_host(self, host: str):
        """Generate a leaf certificate for a specific host, signed by our CA."""
        cert_path = os.path.join(self.cert_dir, f"{host}.crt")
        key_path = os.path.join(self.cert_dir, f"{host}.key")
        
        # In a real dynamic proxy, we might keep keys in memory or reuse a single wildcard key for efficiency.
        # For simplicity, we generate per host.
        
        if os.path.exists(cert_path) and os.path.exists(key_path):
             return cert_path, key_path

        # Generate Key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Generate CSR/Cert
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, host),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.ca_cert.subject
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(host)]),
            critical=False,
        ).sign(self.ca_key, hashes.SHA256())

        # Write
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
            
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            
        return cert_path, key_path
