import base64
import json
import os
from datetime import datetime
from typing import Dict, Optional

import httpx
from fastmcp.server.dependencies import get_http_headers
from prowler_mcp_server import __version__
from prowler_mcp_server.lib.logger import logger


class ProwlerAppAuth:
    """Handles authentication and token management for Prowler App API."""

    def __init__(
        self,
        mode: str = os.getenv("PROWLER_MCP_MODE", "stdio"),
        base_url: str = os.getenv("PROWLER_API_BASE_URL", "https://api.prowler.com"),
    ):
        self.base_url = base_url.rstrip("/")
        logger.info(f"Using Prowler App API base URL: {self.base_url}")
        self.mode = mode

        if mode == "stdio":  # STDIO mode
            self.email = os.getenv("PROWLER_APP_EMAIL")
            self.password = os.getenv("PROWLER_APP_PASSWORD")
            self.tenant_id = os.getenv("PROWLER_APP_TENANT_ID", None)

            if not self.email or not self.password:
                raise ValueError(
                    "PROWLER_APP_EMAIL and PROWLER_APP_PASSWORD environment variables are required"
                )
        else:
            self.email = None
            self.password = None
            self.tenant_id = None

        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None

    def _parse_jwt(self, token: str) -> Optional[Dict]:
        """Parse JWT token and return payload, similar to JS parseJwt function."""
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
        """Authenticate with Prowler App API and return access token."""
        logger.info("Starting authentication with Prowler App API")
        if self.mode == "stdio":
            async with httpx.AsyncClient() as client:
                try:
                    # Prepare JSON:API formatted request body
                    auth_attributes = {"email": self.email, "password": self.password}
                    if self.tenant_id:
                        auth_attributes["tenant_id"] = self.tenant_id

                    request_body = {
                        "data": {
                            "type": "tokens",
                            "attributes": auth_attributes,
                        }
                    }

                    response = await client.post(
                        f"{self.base_url}/api/v1/tokens",
                        json=request_body,
                        headers={
                            "Content-Type": "application/vnd.api+json",
                            "Accept": "application/vnd.api+json",
                        },
                    )
                    response.raise_for_status()

                    data = response.json()
                    # Extract token from JSON:API response format
                    self.access_token = (
                        data.get("data", {}).get("attributes", {}).get("access")
                    )
                    self.refresh_token = (
                        data.get("data", {}).get("attributes", {}).get("refresh")
                    )

                    if not self.access_token:
                        raise ValueError("Token not found in response")

                    logger.info("Authentication successful")

                    return self.access_token

                except httpx.HTTPStatusError as e:
                    logger.error(
                        f"Authentication failed with HTTP status {e.response.status_code}: {e.response.text}"
                    )
                    raise ValueError(f"Authentication failed: {e.response.text}")
                except Exception as e:
                    logger.error(f"Authentication failed with error: {e}")
                    raise ValueError(f"Authentication failed: {e}")
        elif self.mode == "http":
            headers = get_http_headers()
            access_token = headers.get("authorization", None)

            # Validate the token
            if access_token:
                if access_token.startswith("Bearer "):
                    access_token = access_token.replace("Bearer ", "")

                payload = self._parse_jwt(access_token)
                if not payload:
                    raise ValueError("Invalid JWT token format")

                # Check if token is expired
                now = int(datetime.now().timestamp())
                exp = payload.get("exp", 0)
                if exp <= now:
                    raise ValueError("Token has expired")
            else:
                raise ValueError("No authorization token provided")

            # Don't cache tokens in HTTP mode to prevent sharing between clients
            return access_token
        else:
            raise ValueError(f"Invalid mode: {self.mode}")

    async def refresh_access_token(self) -> str:
        """Refresh the access token using the refresh token."""
        if not self.refresh_token:
            logger.info("No refresh token available, performing full authentication")
            return await self.authenticate()

        logger.info("Refreshing access token")

        async with httpx.AsyncClient() as client:
            try:
                # Prepare JSON:API formatted request body for refresh
                request_body = {
                    "data": {
                        "type": "tokens",
                        "attributes": {"refresh": self.refresh_token},
                    }
                }

                response = await client.post(
                    f"{self.base_url}/api/v1/tokens/refresh",
                    json=request_body,
                    headers={
                        "Content-Type": "application/vnd.api+json",
                        "Accept": "application/vnd.api+json",
                    },
                )
                response.raise_for_status()

                data = response.json()
                # Extract new access token from JSON:API response
                self.access_token = (
                    data.get("data", {}).get("attributes", {}).get("access")
                )
                logger.info("Token refresh successful")

                return self.access_token

            except httpx.HTTPStatusError as e:
                logger.warning(
                    f"Token refresh failed, attempting re-authentication: {e}"
                )
                # If refresh fails, re-authenticate
                return await self.authenticate()

    async def get_valid_token(self) -> str:
        """Get a valid access token, checking JWT expiry."""

        if self.mode == "http":
            # In HTTP mode, always authenticate fresh to prevent token sharing between clients
            return await self.authenticate()
        else:
            # In STDIO mode, cache tokens for efficiency
            current_token = self.access_token
            need_new_token = True

            if current_token:
                payload = self._parse_jwt(current_token)

                if payload:
                    now = int(datetime.now().timestamp())
                    time_left = payload.get("exp", 0) - now

                    if time_left > 120:  # 2 minutes margin
                        need_new_token = False

            if need_new_token:
                token = await self.authenticate()

                # Verify the new token
                payload = self._parse_jwt(token)

                return token
            else:
                return current_token

    def get_headers(self, token: str) -> Dict[str, str]:
        """Get headers for API requests with authentication."""
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/vnd.api+json",
            "Accept": "application/vnd.api+json",
            "User-Agent": f"prowler-mcp-server/{__version__}",
        }

        # Add tenant ID header if available
        if self.tenant_id:
            headers["X-Tenant-Id"] = self.tenant_id

        return headers
