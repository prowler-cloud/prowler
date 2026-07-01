"""Cloudflare provider config schema with safety bounds."""

from typing import Optional

from pydantic import Field

from prowler.config.schema.base import ProviderConfigBase


class CloudflareProviderConfig(ProviderConfigBase):
    """Cloudflare provider configuration schema.

    Defines optional configuration parameters for Cloudflare security checks,
    including API retry behavior.
    """

    max_retries: Optional[int] = Field(
        default=None,
        ge=0,
        le=10,
        description=(
            "Max retries for Cloudflare API requests. Range: 0..10 (0 disables retries)."
        ),
    )
