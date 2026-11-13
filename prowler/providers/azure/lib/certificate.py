import re
from typing import Optional

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

# Reject bundles larger than this before parsing: legitimate PEM and PFX
# bundles are under ~10 KiB, and a multi-MB payload would waste memory on
# the doubling that base64 decoding plus PKCS#12/PEM parsing perform.
_MAX_CERTIFICATE_BUNDLE_BYTES = 50 * 1024

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


def validate_certificate_bundle(certificate_data: bytes) -> bytes:
    """Validate the bundle and return a normalized copy safe for azure-identity.

    Accepts either a PKCS#12/PFX blob (encrypted or unencrypted with a null
    password) or a concatenated PEM bundle. Raises ``ValueError`` when the
    payload exceeds the maximum bundle size, is missing a certificate,
    missing a private key, or contains a pair whose public keys do not
    match. Raises ``TypeError`` for password-protected PEM private keys,
    which cryptography surfaces from
    ``load_pem_private_key(..., password=None)``.

    The normalized bytes always place the leaf certificate before the private
    key so ``azure.identity.CertificateCredential`` — which uses the first
    ``BEGIN CERTIFICATE`` block to compute the credential thumbprint — never
    picks an intermediate CA over the matching leaf. PKCS#12 blobs are
    returned as-is.
    """
    if len(certificate_data) > _MAX_CERTIFICATE_BUNDLE_BYTES:
        raise ValueError(
            f"the payload exceeds the maximum bundle size of "
            f"{_MAX_CERTIFICATE_BUNDLE_BYTES} bytes"
        )
    try:
        private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
            certificate_data, None, default_backend()
        )
    except (ValueError, UnsupportedAlgorithm) as error:
        # `load_key_and_certificates` also raises `ValueError` when the
        # PKCS#12 archive is password-protected (message text: "Invalid
        # password or PKCS12 data"). Fall through to the PEM parser only
        # when the payload smells like PEM; otherwise raise a specific
        # error so the caller does not see the misleading "missing
        # certificate or key" message from `_normalize_pem_bundle`.
        if b"-----BEGIN" not in certificate_data:
            raise ValueError(
                "the payload is not a valid PEM bundle nor an unencrypted "
                "PKCS#12 archive; password-protected PKCS#12 archives are "
                "not supported"
            ) from error
        return _normalize_pem_bundle(certificate_data)

    if private_key is None:
        raise ValueError("the PKCS#12 archive does not contain a private key")
    if certificate is None and not additional_certs:
        raise ValueError("the PKCS#12 archive does not contain a certificate")

    encoding = serialization.Encoding.DER
    public_format = serialization.PublicFormat.SubjectPublicKeyInfo
    key_public_bytes = private_key.public_key().public_bytes(encoding, public_format)
    if (
        certificate is not None
        and certificate.public_key().public_bytes(encoding, public_format)
        == key_public_bytes
    ):
        # PKCS#12 blobs are consumed directly by azure-identity; no reordering.
        return certificate_data

    # Some `openssl pkcs12 -export -certfile` workflows write the leaf
    # certificate into the additional-certs bag instead of the primary
    # slot. azure-identity reads the primary certificate for the
    # thumbprint, so accepting the archive as-is would authenticate
    # against the wrong thumbprint. Detect that case and raise an
    # actionable error rather than the opaque "does not match" message.
    for candidate in additional_certs or ():
        if (
            candidate.public_key().public_bytes(encoding, public_format)
            == key_public_bytes
        ):
            raise ValueError(
                "the PKCS#12 archive has the certificate matching the "
                "private key in the additional-certs bag; re-export the "
                "archive with the leaf certificate as the primary entry"
            )
    raise ValueError("the certificate does not match the private key")


def _normalize_pem_bundle(certificate_data: bytes) -> bytes:
    """Validate a PEM bundle and return it with the matching leaf first."""
    certificate_blocks = _CERTIFICATE_BLOCK_RE.findall(certificate_data)
    private_key_matches = list(_PRIVATE_KEY_BLOCK_RE.finditer(certificate_data))

    if not certificate_blocks or not private_key_matches:
        raise ValueError("the payload must contain a certificate and its private key")

    # A bundle may carry more than one private key block (e.g. legacy tools
    # export both an RSA and a PKCS#8 copy). Try each in order; preserve the
    # first parse error so that a single encrypted key still surfaces the
    # TypeError callers rely on to route to the typed certificate errors.
    first_key_error: Optional[Exception] = None
    for key_match in private_key_matches:
        try:
            private_key = serialization.load_pem_private_key(
                key_match.group(), password=None, backend=default_backend()
            )
        except (ValueError, TypeError) as error:
            if first_key_error is None:
                first_key_error = error
            continue
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
                # azure-identity's CertificateCredential uses the first BEGIN
                # CERTIFICATE block to compute the credential thumbprint. Put
                # the matching leaf first so authentication uses the correct
                # certificate regardless of the bundle's original ordering.
                return pem_block + b"\n" + key_match.group() + b"\n"

    if first_key_error is not None:
        raise first_key_error
    raise ValueError("the certificate does not match the private key")
