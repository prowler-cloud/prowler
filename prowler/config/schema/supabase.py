from typing import Optional

from pydantic import Field

from prowler.config.schema.base import ProviderConfigBase


class SupabaseProviderConfig(ProviderConfigBase):
    """Supabase provider configuration schema."""

    max_retries: Optional[int] = Field(
        default=None,
        ge=0,
        le=10,
        description="Maximum retries for Supabase API requests. Range: 0..10.",
    )
