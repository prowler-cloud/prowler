import re

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12


def validate_certificate_bundle(certificate_data: bytes) -> None:
    """Validate that certificate data contains a matching certificate and key."""
    try:
        private_key, certificate, _ = pkcs12.load_key_and_certificates(
            certificate_data, None, default_backend()
        )
    except ValueError:
        certificate_match = re.search(
            rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            certificate_data,
            re.DOTALL,
        )
        private_key_match = re.search(
            rb"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----.*?-----END (?:RSA |EC )?PRIVATE KEY-----",
            certificate_data,
            re.DOTALL,
        )
        if not certificate_match or not private_key_match:
            raise ValueError(
                "the payload must contain a certificate and its private key"
            )
        certificate = x509.load_pem_x509_certificate(
            certificate_match.group(), default_backend()
        )
        private_key = serialization.load_pem_private_key(
            private_key_match.group(), password=None, backend=default_backend()
        )

    if certificate is None or private_key is None:
        raise ValueError("the payload must contain a certificate and its private key")

    encoding = serialization.Encoding.DER
    public_format = serialization.PublicFormat.SubjectPublicKeyInfo
    if certificate.public_key().public_bytes(
        encoding, public_format
    ) != private_key.public_key().public_bytes(encoding, public_format):
        raise ValueError("the certificate does not match the private key")
