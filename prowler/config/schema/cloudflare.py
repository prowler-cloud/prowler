"""Cloudflare provider config schema with safety bounds."""

from typing import Optional

from pydantic import Field

from prowler.config.schema.base import ProviderConfigBase


class CloudflareProviderConfig(ProviderConfigBase):
    """Cloudflare provider configuration schema.

    Defines optional configuration parameters for Cloudflare security checks,
    including API retry behavior, account member and API token thresholds,
    and Workers secret scanning.
    """

    max_retries: Optional[int] = Field(
        default=None,
        ge=0,
        le=10,
        description=(
            "Max retries for Cloudflare API requests. Range: 0..10 (0 disables retries)."
        ),
    )
    max_super_admins: Optional[int] = Field(
        default=None,
        ge=1,
        le=50,
        description=(
            "Maximum Super Administrators allowed per account before flagging. "
            "Range: 1..50 (defaults to 3)."
        ),
    )
    max_unused_api_token_days: Optional[int] = Field(
        default=None,
        ge=7,
        le=365,
        description=(
            "Days without use after which an active API token is flagged. "
            "Range: 7..365 (defaults to 90)."
        ),
    )
    secrets_ignore_patterns: Optional[list[str]] = Field(
        default=None,
        description=(
            "Regex patterns whose matches are excluded from secret scanning "
            "of Workers plain text bindings."
        ),
    )
    secrets_validate: Optional[bool] = Field(
        default=None,
        description=(
            "Validate discovered secrets against the provider APIs (live check). "
            "Makes outbound network calls that authenticate with the discovered "
            "secret. Disabled by default."
        ),
    )
