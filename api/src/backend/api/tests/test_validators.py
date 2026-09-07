import socket
from datetime import UTC, datetime, timedelta

import pytest
from api.validators import (
    resolve_lighthouse_openai_compatible_host,
    validate_certificate_bundle,
    validate_lighthouse_openai_compatible_base_url,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from django.core.exceptions import ValidationError
from django.test import override_settings


def _certificate_and_key():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Prowler")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )
    return certificate, private_key


def test_certificate_bundle_rejects_key_only_pkcs12():
    _, private_key = _certificate_and_key()
    key_only_pkcs12 = pkcs12.serialize_key_and_certificates(
        name=b"prowler",
        key=private_key,
        cert=None,
        cas=None,
        encryption_algorithm=serialization.NoEncryption(),
    )

    with pytest.raises(ValueError, match="does not contain a certificate"):
        validate_certificate_bundle(key_only_pkcs12)


def test_certificate_bundle_rejects_mismatched_pem_key():
    certificate, _ = _certificate_and_key()
    different_private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    mismatched_bundle = certificate.public_bytes(
        serialization.Encoding.PEM
    ) + different_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    with pytest.raises(ValueError, match="does not match"):
        validate_certificate_bundle(mismatched_bundle)


def test_certificate_bundle_rejects_encrypted_pem_key():
    # `cryptography.load_pem_private_key(..., password=None)` raises
    # TypeError for encrypted keys; the API relies on that specific type
    # to route to `azure-certificate-content`, not a generic 500.
    certificate, _ = _certificate_and_key()
    encrypted_key_pem = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    ).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"prowler"),
    )
    encrypted_bundle = (
        certificate.public_bytes(serialization.Encoding.PEM) + encrypted_key_pem
    )

    with pytest.raises(TypeError):
        validate_certificate_bundle(encrypted_bundle)


def test_certificate_bundle_normalizes_multi_key_bundle_when_second_key_matches():
    # A PEM bundle may legitimately carry more than one private key block
    # (e.g. legacy tools that export both RSA and PKCS#8 encodings).
    # The validator must find the key that actually pairs with the leaf
    # instead of stopping at the first `-----BEGIN PRIVATE KEY-----`.
    leaf_cert, leaf_key = _certificate_and_key()
    _, unrelated_key = _certificate_and_key()

    leaf_cert_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)
    unrelated_key_pem = unrelated_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    leaf_key_pem = leaf_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    bundle = leaf_cert_pem + unrelated_key_pem + leaf_key_pem

    normalized = validate_certificate_bundle(bundle)

    # The leaf still leads (azure-identity's thumbprint invariant) and the
    # matching key is the one paired in the normalized output.
    assert normalized.startswith(leaf_cert_pem)
    assert leaf_key_pem in normalized


def test_certificate_bundle_rejects_oversized_payload():
    # Legitimate PEM/PFX bundles are well under 10 KiB. Reject anything
    # above the 50 KiB cap before base64 decoding + PKCS#12/PEM parsing
    # allocate the doubled memory a multi-MB payload would need.
    from prowler.providers.azure.lib.certificate import (
        _MAX_CERTIFICATE_BUNDLE_BYTES,
    )

    oversized = b"\x00" * (_MAX_CERTIFICATE_BUNDLE_BYTES + 1)

    with pytest.raises(ValueError, match="maximum bundle size"):
        validate_certificate_bundle(oversized)


def test_lighthouse_base_url_rejects_http_scheme():
    with pytest.raises(ValidationError, match="HTTPS"):
        validate_lighthouse_openai_compatible_base_url(
            "http://openrouter.ai/api/v1",
            resolve_dns=False,
        )


@pytest.mark.parametrize(
    "base_url",
    [
        "https://openrouter.ai:0/api/v1",
        "https://openrouter.ai:-1/api/v1",
        "https://openrouter.ai:65536/api/v1",
        "https://openrouter.ai:invalid/api/v1",
    ],
)
def test_lighthouse_base_url_rejects_invalid_port(base_url):
    with pytest.raises(ValidationError, match="port is invalid"):
        validate_lighthouse_openai_compatible_base_url(
            base_url,
            resolve_dns=False,
        )


@pytest.mark.parametrize("port", [1, 65535])
def test_lighthouse_base_url_accepts_valid_port_boundaries(port):
    assert (
        validate_lighthouse_openai_compatible_base_url(
            f"https://openrouter.ai:{port}/api/v1",
            resolve_dns=False,
        )
        is None
    )


def test_lighthouse_base_url_rejects_localhost():
    with pytest.raises(ValidationError, match="external public endpoint"):
        validate_lighthouse_openai_compatible_base_url(
            "https://localhost/v1",
            resolve_dns=False,
        )


@pytest.mark.parametrize("ip_address", ["10.0.0.1", "172.16.0.1", "192.168.1.1"])
def test_lighthouse_base_url_rejects_private_ip_literal(ip_address):
    with pytest.raises(ValidationError, match="external public endpoint"):
        validate_lighthouse_openai_compatible_base_url(
            f"https://{ip_address}/v1",
            resolve_dns=False,
        )


def test_lighthouse_base_url_rejects_metadata_ip_literal():
    with pytest.raises(ValidationError, match="external public endpoint"):
        validate_lighthouse_openai_compatible_base_url(
            "https://169.254.169.254/latest/meta-data",
            resolve_dns=False,
        )


@pytest.mark.parametrize(
    "base_url",
    [
        "https://[::ffff:169.254.169.254]/v1",
        "https://[64:ff9b::a9fe:a9fe]/v1",
        "https://[2002:a9fe:a9fe::]/v1",
    ],
)
def test_lighthouse_base_url_rejects_embedded_non_global_ip(base_url):
    with pytest.raises(ValidationError, match="external public endpoint"):
        validate_lighthouse_openai_compatible_base_url(
            base_url,
            resolve_dns=False,
        )


@pytest.mark.parametrize(
    "base_url",
    [
        "https://[::ffff:93.184.216.34]/v1",
        "https://[64:ff9b::5db8:d822]/v1",
        "https://[2002:5db8:d822::]/v1",
    ],
)
def test_lighthouse_base_url_accepts_embedded_public_ip(base_url):
    assert (
        validate_lighthouse_openai_compatible_base_url(
            base_url,
            resolve_dns=False,
        )
        is None
    )


def test_lighthouse_base_url_accepts_hostname_without_dns_resolution():
    assert (
        validate_lighthouse_openai_compatible_base_url(
            "https://openrouter.ai/api/v1",
            resolve_dns=False,
        )
        is None
    )


def test_lighthouse_base_url_rejects_post_dns_internal_address(monkeypatch):
    def resolve_to_metadata(*_args, **_kwargs):
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("169.254.169.254", 443),
            )
        ]

    monkeypatch.setattr("api.validators.socket.getaddrinfo", resolve_to_metadata)

    with pytest.raises(ValidationError, match="external public endpoint"):
        validate_lighthouse_openai_compatible_base_url(
            "https://metadata.example.test/v1"
        )


def test_lighthouse_base_url_accepts_public_resolved_address(monkeypatch):
    def resolve_to_public(*_args, **_kwargs):
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("93.184.216.34", 443),
            )
        ]

    monkeypatch.setattr("api.validators.socket.getaddrinfo", resolve_to_public)

    assert (
        validate_lighthouse_openai_compatible_base_url("https://openrouter.ai/api/v1")
        is None
    )


@override_settings(
    LIGHTHOUSE_AI_OPENAI_COMPATIBLE_ALLOWED_HOSTS=["custom-openai.internal"]
)
def test_lighthouse_base_url_accepts_allowlisted_host_without_resolution(monkeypatch):
    def fail_resolution(*_args, **_kwargs):
        raise AssertionError("allowlisted hosts must not be resolved")

    monkeypatch.setattr("api.validators.socket.getaddrinfo", fail_resolution)

    assert (
        validate_lighthouse_openai_compatible_base_url(
            "https://custom-openai.internal/v1"
        )
        is None
    )


@override_settings(
    LIGHTHOUSE_AI_OPENAI_COMPATIBLE_ALLOWED_HOSTS=["custom-openai.internal"]
)
def test_lighthouse_resolve_returns_allowlisted_hostname_unpinned():
    assert resolve_lighthouse_openai_compatible_host(
        "Custom-OpenAI.internal.", 443
    ) == ("custom-openai.internal",)


@override_settings(LIGHTHOUSE_AI_OPENAI_COMPATIBLE_ALLOWED_HOSTS=["localhost"])
def test_lighthouse_base_url_accepts_allowlisted_blocked_host():
    assert (
        validate_lighthouse_openai_compatible_base_url(
            "https://localhost/v1",
            resolve_dns=False,
        )
        is None
    )


@override_settings(LIGHTHOUSE_AI_OPENAI_COMPATIBLE_ALLOWED_HOSTS=["10.0.0.1"])
def test_lighthouse_base_url_accepts_allowlisted_private_ip_literal():
    assert (
        validate_lighthouse_openai_compatible_base_url(
            "https://10.0.0.1/v1",
            resolve_dns=False,
        )
        is None
    )


@override_settings(
    LIGHTHOUSE_AI_OPENAI_COMPATIBLE_ALLOWED_HOSTS=[" Custom-OpenAI.Internal. "]
)
def test_lighthouse_allowlist_entries_are_normalized():
    assert (
        validate_lighthouse_openai_compatible_base_url(
            "https://custom-openai.internal/v1",
            resolve_dns=False,
        )
        is None
    )


@override_settings(
    LIGHTHOUSE_AI_OPENAI_COMPATIBLE_ALLOWED_HOSTS=["custom-openai.internal"]
)
def test_lighthouse_base_url_rejects_host_not_in_allowlist():
    with pytest.raises(ValidationError, match="external public endpoint"):
        validate_lighthouse_openai_compatible_base_url(
            "https://localhost/v1",
            resolve_dns=False,
        )


@override_settings(LIGHTHOUSE_AI_OPENAI_COMPATIBLE_ALLOWED_HOSTS=[""])
def test_lighthouse_allowlist_ignores_empty_entries():
    with pytest.raises(ValidationError, match="external public endpoint"):
        validate_lighthouse_openai_compatible_base_url(
            "https://localhost/v1",
            resolve_dns=False,
        )


@override_settings(
    LIGHTHOUSE_AI_OPENAI_COMPATIBLE_ALLOWED_HOSTS=["custom-openai.internal"]
)
def test_lighthouse_base_url_allowlisted_host_still_requires_https():
    with pytest.raises(ValidationError, match="HTTPS"):
        validate_lighthouse_openai_compatible_base_url(
            "http://custom-openai.internal/v1",
            resolve_dns=False,
        )
