import socket

import pytest
from api.validators import validate_lighthouse_openai_compatible_base_url
from django.core.exceptions import ValidationError


def test_lighthouse_base_url_rejects_metadata_ip_literal():
    with pytest.raises(ValidationError, match="external public endpoint"):
        validate_lighthouse_openai_compatible_base_url(
            "https://169.254.169.254/latest/meta-data",
            resolve_dns=False,
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


def test_lighthouse_base_url_enforces_allowed_hosts(monkeypatch):
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

    with pytest.raises(ValidationError, match="approved provider"):
        validate_lighthouse_openai_compatible_base_url(
            "https://webhook.site/example/v1",
            allowed_hosts=("openrouter.ai",),
        )
