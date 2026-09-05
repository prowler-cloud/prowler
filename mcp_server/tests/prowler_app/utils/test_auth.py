"""Tests for Prowler API authentication.

Reference for later branches: ``ProwlerAppAuth`` resolves its ``mode`` and
``base_url`` in default arguments, which Python evaluates once at module import.
``monkeypatch.setenv`` therefore has no effect on them -- always pass ``mode=``
and ``base_url=`` explicitly, as these tests do.
"""

import base64
import json

import pytest

from prowler_mcp_server.lib.errors import CredentialError
from prowler_mcp_server.prowler_app.utils.auth import ProwlerAppAuth
from tests.helpers.tokens import FAKE_API_KEY, MALFORMED_API_KEY, fake_jwt


async def test_stdio_mode_reads_the_api_key_from_the_environment():
    """In STDIO transport the key comes from the process environment."""
    auth = ProwlerAppAuth(mode="stdio")

    assert await auth.get_valid_token() == FAKE_API_KEY


def test_stdio_mode_rejects_a_key_without_the_prowler_prefix(
    monkeypatch: pytest.MonkeyPatch,
):
    """A key that is not `pk_`-prefixed is refused at construction.

    Failing here rather than on the first API call is what turns a
    misconfiguration into an immediate, readable startup error.
    """
    monkeypatch.setenv("PROWLER_API_KEY", MALFORMED_API_KEY)

    with pytest.raises(ValueError, match="Prowler API key format is incorrect"):
        ProwlerAppAuth(mode="stdio")


async def test_http_mode_accepts_a_bearer_api_key(http_request_headers):
    """In HTTP transport the token comes from the request's Authorization header."""
    http_request_headers(authorization=f"Bearer {FAKE_API_KEY}")

    auth = ProwlerAppAuth(mode="http")

    assert await auth.get_valid_token() == FAKE_API_KEY


def _jwt_with_payload(payload: object) -> str:
    """Mint an unsigned JWT carrying an arbitrary payload.

    ``fake_jwt`` always writes a well-formed object, so the malformed payloads
    below are built here instead.
    """
    encoded = (
        base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    )
    return f"header.{encoded}.fake-signature-not-verified"


async def test_http_mode_accepts_a_lowercase_bearer_scheme(http_request_headers):
    """Authentication scheme names are case-insensitive (RFC 7235)."""
    http_request_headers(authorization=f"bearer {FAKE_API_KEY}")

    auth = ProwlerAppAuth(mode="http")

    assert await auth.get_valid_token() == FAKE_API_KEY


async def test_http_mode_strips_only_the_scheme_prefix(http_request_headers):
    """A token that repeats the scheme keeps it: only the prefix is removed."""
    token = f"{FAKE_API_KEY}_Bearer_suffix"
    http_request_headers(authorization=f"Bearer {token}")

    auth = ProwlerAppAuth(mode="http")

    assert await auth.get_valid_token() == token


async def test_http_mode_rejects_an_authorization_header_without_a_token(
    http_request_headers,
):
    """A bare scheme carries no credential to authenticate with."""
    http_request_headers(authorization="Bearer   ")

    auth = ProwlerAppAuth(mode="http")

    with pytest.raises(CredentialError, match="'Bearer <token>' form"):
        await auth.get_valid_token()


async def test_http_mode_rejects_a_jwt_whose_payload_is_not_an_object(
    http_request_headers,
):
    """A payload that decodes to a list has no claims, so it is a bad credential.

    Without the type check it would reach `payload.get` and fail as an
    unclassified `AttributeError`, which the client only sees masked.
    """
    http_request_headers(authorization=f"Bearer {_jwt_with_payload(['exp'])}")

    auth = ProwlerAppAuth(mode="http")

    with pytest.raises(CredentialError, match="not a readable JWT"):
        await auth.get_valid_token()


@pytest.mark.parametrize(
    ("payload", "case"),
    [
        ({"sub": "user"}, "missing"),
        ({"exp": "1700000000"}, "string"),
        ({"exp": None}, "null"),
    ],
)
async def test_http_mode_rejects_a_jwt_without_a_numeric_expiration(
    http_request_headers, payload: dict, case: str
):
    """`exp` is a numeric date: comparing anything else raises a `TypeError`."""
    http_request_headers(authorization=f"Bearer {_jwt_with_payload(payload)}")

    auth = ProwlerAppAuth(mode="http")

    with pytest.raises(CredentialError, match="no readable 'exp' expiration claim"):
        await auth.get_valid_token()


async def test_http_mode_rejects_an_expired_jwt(http_request_headers):
    """An expired JWT is refused locally instead of being forwarded to the API."""
    http_request_headers(authorization=f"Bearer {fake_jwt(expires_in=-60)}")

    auth = ProwlerAppAuth(mode="http")

    with pytest.raises(CredentialError, match="The token has expired"):
        await auth.get_valid_token()


def test_api_keys_and_jwts_use_different_authorization_schemes():
    """Prowler API keys authenticate with `Api-Key`, JWTs with `Bearer`."""
    auth = ProwlerAppAuth(mode="stdio")

    assert auth.get_headers(FAKE_API_KEY)["Authorization"] == f"Api-Key {FAKE_API_KEY}"

    jwt = fake_jwt()
    assert auth.get_headers(jwt)["Authorization"] == f"Bearer {jwt}"
