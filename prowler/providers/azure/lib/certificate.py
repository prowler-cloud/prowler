import re

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

_CERTIFICATE_BLOCK_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)

# Covers PKCS#8 (encrypted or not), legacy RSA/EC/DSA and OpenSSH PEM labels.
# The actual decoding is delegated to `load_pem_private_key` below.
_PRIVATE_KEY_BLOCK_RE = re.compile(
    rb"-----BEGIN (?:ENCRYPTED |OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----"
    rb".*?"
    rb"-----END (?:ENCRYPTED |OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----",
    re.DOTALL,
)


def validate_certificate_bundle(certificate_data: bytes) -> None:
    """Validate that certificate data contains a matching certificate and key.

    Accepts either a PKCS#12/PFX blob (encrypted or unencrypted with a null
    password) or a concatenated PEM bundle. Raises `ValueError` with a
    diagnostic message when the payload is missing a certificate, missing a
    private key, or contains a pair whose public keys do not match.
    """
    try:
        private_key, certificate, _ = pkcs12.load_key_and_certificates(
            certificate_data, None, default_backend()
        )
    except (ValueError, UnsupportedAlgorithm):
        # Not PKCS#12, or PKCS#12 uses a cipher this build cannot decrypt.
        # Fall through to the PEM path.
        certificate, private_key = _load_pem_bundle(certificate_data)

    if certificate is None or private_key is None:
        raise ValueError("the payload must contain a certificate and its private key")

    encoding = serialization.Encoding.DER
    public_format = serialization.PublicFormat.SubjectPublicKeyInfo
    if certificate.public_key().public_bytes(
        encoding, public_format
    ) != private_key.public_key().public_bytes(encoding, public_format):
        raise ValueError("the certificate does not match the private key")


def _load_pem_bundle(certificate_data: bytes):
    """Return the (certificate, private_key) pair from a PEM bundle.

    Walks every certificate block so bundles that place the intermediate CA
    before the leaf (openssl/Key Vault exports) still pair correctly.
    """
    certificate_blocks = _CERTIFICATE_BLOCK_RE.findall(certificate_data)
    private_key_match = _PRIVATE_KEY_BLOCK_RE.search(certificate_data)

    if not certificate_blocks or not private_key_match:
        raise ValueError("the payload must contain a certificate and its private key")

    private_key = serialization.load_pem_private_key(
        private_key_match.group(), password=None, backend=default_backend()
    )
    key_public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    for pem_block in certificate_blocks:
        candidate = x509.load_pem_x509_certificate(pem_block, default_backend())
        candidate_public_bytes = candidate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if candidate_public_bytes == key_public_bytes:
            return candidate, private_key

    # No match. Return the first cert so the caller's public-key comparison
    # raises the canonical "certificate does not match" error.
    return (
        x509.load_pem_x509_certificate(certificate_blocks[0], default_backend()),
        private_key,
    )
