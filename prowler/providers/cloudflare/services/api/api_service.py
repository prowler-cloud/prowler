from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.cloudflare.lib.service.service import CloudflareService


class API(CloudflareService):
    """Retrieve Cloudflare API tokens for the authenticated user."""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.tokens: list["CloudflareAPIToken"] = []
        self._list_api_tokens()

    def _list_api_tokens(self) -> None:
        """List all API tokens for the authenticated user."""
        logger.info("API - Listing API tokens...")
        try:
            seen_token_ids: set[str] = set()
            for token in self.client.user.tokens.list():
                token_id = getattr(token, "id", None)
                if not token_id:
                    continue
                if token_id in seen_token_ids:
                    continue
                seen_token_ids.add(token_id)

                # Extract IP condition details
                condition = getattr(token, "condition", None)
                request_ip = getattr(condition, "request_ip", None) if condition else None
                ip_in = getattr(request_ip, "in_", None) if request_ip else None
                ip_not_in = getattr(request_ip, "not_in", None) if request_ip else None

                self.tokens.append(
                    CloudflareAPIToken(
                        id=token_id,
                        name=getattr(token, "name", None),
                        status=getattr(token, "status", None),
                        ip_allow_list=ip_in or [],
                        ip_deny_list=ip_not_in or [],
                        expires_on=getattr(token, "expires_on", None),
                        issued_on=getattr(token, "issued_on", None),
                        last_used_on=getattr(token, "last_used_on", None),
                        modified_on=getattr(token, "modified_on", None),
                    )
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class CloudflareAPIToken(BaseModel):
    """Cloudflare API token representation."""

    id: str
    name: Optional[str] = None
    status: Optional[str] = None
    ip_allow_list: list[str] = Field(default_factory=list)
    ip_deny_list: list[str] = Field(default_factory=list)
    expires_on: Optional[datetime] = None
    issued_on: Optional[datetime] = None
    last_used_on: Optional[datetime] = None
    modified_on: Optional[datetime] = None
