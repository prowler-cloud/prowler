import socket

import pytest
from api.validators import (
    resolve_lighthouse_openai_compatible_host,
    validate_lighthouse_openai_compatible_base_url,
)
from django.core.exceptions import ValidationError
from django.test import override_settings


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
