import base64
import json
import os
from datetime import datetime
from typing import Dict, Optional

from fastmcp.server.dependencies import get_http_headers
from prowler_mcp_server import __version__
from prowler_mcp_server.lib.logger import logger


class ProwlerAppAuth:
    """Handles authentication for Prowler App API using API keys or JWT tokens."""

    def __init__(
        self,
        mode: str = os.getenv("PROWLER_MCP_TRANSPORT_MODE", "stdio"),
        base_url: str = os.getenv("API_BASE_URL", "https://api.prowler.com/api/v1"),
    ):
        self.base_url = base_url.rstrip("/")
        logger.info(f"Using Prowler App API base URL: {self.base_url}")
        self.mode = mode
        self.access_token: Optional[str] = None
        self.api_key: Optional[str] = None

        if mode == "stdio":  # STDIO mode
            self.api_key = os.getenv("PROWLER_APP_API_KEY")

            if not self.api_key:
                raise ValueError("PROWLER_APP_API_KEY environment variable is required")

            if not self.api_key.startswith("pk_"):
                raise ValueError("Prowler App API key format is incorrect")

    def _parse_jwt(self, token: str) -> Optional[Dict]:
        """Parse JWT token and return payload

        Args:
            token: JWT token to parse

        Returns:
            Parsed JWT payload, or None if parsing fails
        """
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
            return json.loads(decoded)
        except Exception as e:
            logger.warning(f"Failed to parse JWT token: {e}")
            return None

    async def authenticate(self) -> str:
        """Authenticate and return token (API key for STDIO, API key or JWT for HTTP)."""
        if self.mode == "http":
            headers = get_http_headers()
            authorization_header = headers.get("authorization", None)

            if not authorization_header:
                raise ValueError("No authorization header provided")

            # Extract token from Bearer header
            if authorization_header.startswith("Bearer "):
                token = authorization_header.replace("Bearer ", "")
            else:
                raise ValueError(
                    "Invalid authorization header format. Expected 'Bearer <token>'"
                )

            # Check if it's an API key or JWT token
            if token.startswith("pk_"):
                # API key - no expiration check needed
                return token
            else:
                # JWT token - validate and check expiration
                payload = self._parse_jwt(token)
                if not payload:
                    raise ValueError("Invalid JWT token format")

                # Check if token is expired
                now = int(datetime.now().timestamp())
                exp = payload.get("exp", 0)
                if exp <= now:
                    raise ValueError("Token has expired")

                return token
        else:
            raise ValueError(f"Invalid mode: {self.mode}")

    async def get_valid_token(self) -> str:
        """Get a valid token (API key or JWT token)."""
        if self.mode == "stdio" and self.api_key:
            return self.api_key
        else:
            return await self.authenticate()

    def get_headers(self, token: str) -> Dict[str, str]:
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
