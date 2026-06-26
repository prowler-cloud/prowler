"""Okta provider config schema with safety bounds."""

from typing import Optional

from pydantic import Field

from prowler.config.schema.base import ProviderConfigBase


class OktaProviderConfig(ProviderConfigBase):
    """Okta provider configuration schema.

    Defines optional configuration parameters for Okta security checks and for
    the provider's API rate-limit handling (proactive request throttling plus
    the SDK retry safety net).
    """

    # Session / check thresholds
    okta_max_session_idle_minutes: Optional[int] = Field(
        default=None,
        ge=1,
        le=1440,
        description=(
            "Maximum acceptable Global Session idle timeout, in minutes. "
            "Range: 1..1440."
        ),
    )
    okta_admin_console_idle_timeout_max_minutes: Optional[int] = Field(
        default=None,
        ge=1,
        le=1440,
        description=(
            "Maximum acceptable Okta Admin Console app idle timeout, in minutes. "
            "Range: 1..1440."
        ),
    )

    # API rate limiting
    okta_requests_per_second: Optional[float] = Field(
        default=None,
        ge=0,
        le=100,
        description=(
            "Maximum aggregate Okta API requests per second. Range: 0..100 "
            "(0 disables throttling)."
        ),
    )
    okta_max_retries: Optional[int] = Field(
        default=None,
        ge=0,
        le=10,
        description=(
            "Max retries on Okta API rate limiting (HTTP 429). Range: 0..10 "
            "(0 disables retries)."
        ),
    )
    okta_request_timeout: Optional[int] = Field(
        default=None,
        ge=0,
        le=3600,
        description=(
            "Per-request timeout in seconds; also the total budget for the SDK "
            "retry loop. Range: 0..3600 (0 disables the timeout)."
        ),
    )
