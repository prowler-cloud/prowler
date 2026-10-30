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
    postgrest_max_rows: Optional[int] = Field(
        default=None,
        ge=1,
        le=1000000,
        description="Maximum rows a Data API request may return. Range: 1..1000000.",
    )
    auth_password_min_length: Optional[int] = Field(
        default=None,
        ge=6,
        le=128,
        description="Minimum password length Supabase Auth must enforce. Range: 6..128.",
    )
    auth_otp_expiry_seconds: Optional[int] = Field(
        default=None,
        ge=60,
        le=86400,
        description="Maximum email OTP validity in seconds. Range: 60..86400.",
    )
