from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.vercel.lib.service.service import VercelService


class VercelAuthToken(BaseModel):
    """Vercel API token representation."""

    id: str
    name: str
    type: Optional[str] = None
    active_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    scopes: list[dict] = Field(default_factory=list)
    origin: Optional[str] = None
    team_id: Optional[str] = None


class Authentication(VercelService):
    """Retrieve Vercel API token metadata for hygiene checks."""

    def __init__(self, provider):
        super().__init__("Authentication", provider)
        self.tokens: dict[str, VercelAuthToken] = {}
        self._list_tokens()

    def _list_tokens(self):
        """List all API tokens for the authenticated user."""
        try:
            data = self._get("/v5/user/tokens")
            if not data:
                return

            tokens = data.get("tokens", [])
            seen_ids: set[str] = set()

            for token in tokens:
                token_id = token.get("id", "")
                if not token_id or token_id in seen_ids:
                    continue
                seen_ids.add(token_id)

                active_at = None
                if token.get("activeAt"):
                    active_at = datetime.fromtimestamp(token["activeAt"] / 1000, tz=timezone.utc)

                created_at = None
                if token.get("createdAt"):
                    created_at = datetime.fromtimestamp(token["createdAt"] / 1000, tz=timezone.utc)

                expires_at = None
                if token.get("expiresAt"):
                    expires_at = datetime.fromtimestamp(token["expiresAt"] / 1000, tz=timezone.utc)

                self.tokens[token_id] = VercelAuthToken(
                    id=token_id,
                    name=token.get("name", "Unnamed Token"),
                    type=token.get("type"),
                    active_at=active_at,
                    created_at=created_at,
                    expires_at=expires_at,
                    scopes=token.get("scopes", []),
                    origin=token.get("origin"),
                    team_id=token.get("teamId") or self.provider.session.team_id,
                )

            logger.info(f"Authentication - Found {len(self.tokens)} token(s)")

        except Exception as error:
            logger.error(
                f"Authentication - Error listing tokens: "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
