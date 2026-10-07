import base64
import json
import os
import pathlib
from datetime import datetime

import jwt
from fastmcp.server.dependencies import get_http_headers

from prowler_mcp_server import __version__
from prowler_mcp_server.lib.errors import CredentialError
from prowler_mcp_server.lib.logger import logger

# The Prowler API signs its JWTs with RS256. Pinning the list keeps a token that
# declares `alg: none`, or an HMAC algorithm keyed with the public key, out.
JWT_ALGORITHMS = ["RS256"]

VERIFYING_KEY_FILE_ENV = "DJANGO_TOKEN_VERIFYING_KEY_FILE"

# Tolerated clock drift between the API that issues a token and this server.
JWT_CLOCK_SKEW_SECONDS = 30


class ProwlerAppAuth:
    """Handles authentication for Prowler API using API keys or JWT tokens."""

    def __init__(
        self,
        mode: str = os.getenv("PROWLER_MCP_TRANSPORT_MODE", "stdio"),
        base_url: str = os.getenv("API_BASE_URL", "https://api.prowler.com/api/v1"),
        jwt_verifying_key: str | None = os.getenv("DJANGO_TOKEN_VERIFYING_KEY"),
    ):
        self.base_url = base_url.rstrip("/")
        logger.info(f"Using Prowler API base URL: {self.base_url}")
        self.mode = mode
        self.access_token: str | None = None
        self.api_key: str | None = None
        # Env files cannot hold a multi-line PEM, so the same escaped-newline
        # form the API accepts for this variable is accepted here.
        self.jwt_verifying_key = (
            jwt_verifying_key.replace("\\n", "\n").strip() or None
            if jwt_verifying_key
            else None
        ) or self._read_verifying_key_file()

        if mode == "stdio":  # STDIO mode
            # PROWLER_API_KEY is the current variable; PROWLER_APP_API_KEY is kept
            # as a backward-compatible fallback so existing setups keep working.
            self.api_key = os.getenv("PROWLER_API_KEY") or os.getenv(
                "PROWLER_APP_API_KEY"
            )

            if not self.api_key:
                raise ValueError("PROWLER_API_KEY environment variable is required")

            if not self.api_key.startswith("pk_"):
                raise ValueError("Prowler API key format is incorrect")
        elif mode == "http" and not self.jwt_verifying_key:
            logger.warning(
                "DJANGO_TOKEN_VERIFYING_KEY is not set: JWT signatures will not be "
                "verified by the MCP server, only their expiration"
            )

    def _parse_jwt(self, token: str) -> dict | None:
        """Decode a JWT payload without verifying it; None if it is unreadable."""
        if not token:
            return None

        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            # Decode base64url
            base64_payload = parts[1]
            # Replace base64url characters
            base64_payload = base64_payload.replace("-", "+").replace("_", "/")

            # Add padding if necessary
            while len(base64_payload) % 4:
                base64_payload += "="

            # Decode and parse JSON
            decoded = base64.b64decode(base64_payload).decode("utf-8")
            payload = json.loads(decoded)

            # A JWT payload is a JSON object. A list or a scalar decodes just as
            # cleanly, so the type is checked here rather than left to blow up as
            # an AttributeError on the first claim read.
            return payload if isinstance(payload, dict) else None
        except Exception as e:
            logger.warning(f"Failed to parse JWT token: {e}")
            return None

    @staticmethod
    def _read_verifying_key_file() -> str | None:
        """Public key from DJANGO_TOKEN_VERIFYING_KEY_FILE, which compose mounts from the API."""
        path = os.getenv(VERIFYING_KEY_FILE_ENV, "").strip()
        if not path:
            return None
        try:
            return pathlib.Path(path).read_text().strip() or None
        except OSError as error:
            logger.warning(
                f"Could not read {VERIFYING_KEY_FILE_ENV} at {path}: {error}"
            )
            return None

    def _verify_jwt(self, token: str) -> dict:
        """Verify the signature and standard time claims; raise CredentialError otherwise."""
        try:
            return jwt.decode(
                token,
                self.jwt_verifying_key,
                algorithms=JWT_ALGORITHMS,
                # The API's audience is deployment-specific and unknown here; the
                # API checks it on every forwarded request.
                options={"require": ["exp"], "verify_aud": False},
                # The API and this server may sit on hosts with drifting clocks,
                # and iat is only checked once a verifying key is configured.
                leeway=JWT_CLOCK_SKEW_SECONDS,
            )
        except jwt.ExpiredSignatureError:
            raise CredentialError("The token has expired")
        except jwt.PyJWTError as e:
            logger.warning(f"Rejected JWT: {type(e).__name__}: {e}")
            raise CredentialError("The token could not be verified")

    def _check_jwt_expiration(self, token: str) -> None:
        """Fallback when no verifying key is configured: readable and not expired."""
        payload = self._parse_jwt(token)
        if not payload:
            raise CredentialError("The token is not a readable JWT")

        # `exp` is a numeric date in the spec, so a missing or non-numeric one
        # makes the token unusable rather than merely stale -- comparing it
        # would raise a TypeError and leave the failure masked as unclassified.
        exp = payload.get("exp")
        if isinstance(exp, bool) or not isinstance(exp, (int, float)):
            raise CredentialError(
                "The token carries no readable 'exp' expiration claim"
            )

        now = int(datetime.now().timestamp())
        if exp <= now:
            raise CredentialError("The token has expired")

    async def authenticate(self) -> str:
        """Authenticate and return token (API key for STDIO, API key or JWT for HTTP)."""
        if self.mode == "http":
            headers = get_http_headers(include={"authorization"})
            authorization_header = headers.get("authorization", None)

            if not authorization_header:
                raise CredentialError("No Authorization header was sent")

            # Extract token from Bearer header. Authentication scheme names are
            # case-insensitive (RFC 7235), and only the scheme prefix is removed:
            # a token that happens to contain the word again keeps it.
            scheme, _, credential = authorization_header.partition(" ")
            token = credential.strip()
            if scheme.lower() != "bearer" or not token:
                raise CredentialError(
                    "The Authorization header is not in 'Bearer <token>' form"
                )

            # Check if it's an API key or JWT token
            if token.startswith("pk_"):
                # API key - no expiration check needed
                return token

            if self.jwt_verifying_key:
                self._verify_jwt(token)
            else:
                self._check_jwt_expiration(token)

            return token
        else:
            # PROWLER_MCP_TRANSPORT_MODE holds something this server does not
            # support. Nothing about a call caused it and nothing about a call
            # can fix it, so it stays unclassified: masked for the model, logged
            # for whoever runs the server.
            raise RuntimeError(f"Invalid mode: {self.mode}")

    async def get_valid_token(self) -> str:
        """Get a valid token (API key or JWT token)."""
        if self.mode == "stdio" and self.api_key:
            return self.api_key
        else:
            return await self.authenticate()

    def get_headers(self, token: str) -> dict[str, str]:
        """Get headers for API requests with authentication."""
        if token.startswith("pk_"):
            authorization_header = f"Api-Key {token}"
        else:
            authorization_header = f"Bearer {token}"

        headers = {
            "Authorization": authorization_header,
            "Content-Type": "application/vnd.api+json",
            "Accept": "application/vnd.api+json",
            "User-Agent": f"prowler-mcp-server/{__version__}",
        }

        return headers
