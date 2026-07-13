"""Okta provider config schema with safety bounds."""

from typing import Annotated, Optional

from pydantic import AfterValidator, Field

from prowler.config.schema.base import ProviderConfigBase

# Lowest non-zero request rate we accept. Below this a scan is paced so slowly
# it becomes impractical (e.g. 0.001 req/s is ~1000s per request, turning a
# routine scan into days or years). 0 stays valid as the "disable throttling"
# sentinel; anything between 0 and this floor is rejected so a typo can never
# stall a scan.
MIN_REQUESTS_PER_SECOND = 0.1


def _validate_requests_per_second(value: Optional[float]) -> Optional[float]:
    """Reject impractically slow non-zero request rates.

    ``0`` (and ``None``) pass through unchanged — ``0`` is the documented
    "disable throttling" sentinel. Any positive value below
    ``MIN_REQUESTS_PER_SECOND`` is rejected; the ``ge``/``le`` bounds on the
    field already handle negatives and the upper cap.
    """
    if value is None or value == 0:
        return value
    if value < MIN_REQUESTS_PER_SECOND:
        raise ValueError(
            f"must be 0 (disable throttling) or >= {MIN_REQUESTS_PER_SECOND}; "
            "smaller rates make scans impractically slow"
        )
    return value


class OktaProviderConfig(ProviderConfigBase):
    """Okta provider configuration schema.

    Bounds the session, idle-timeout and inactivity thresholds consumed by
    the Okta checks, plus the provider's API rate-limit handling (proactive
    request throttling and the SDK retry safety net). Every field is optional:
    when omitted (or dropped for being out of range) the check falls back to
    its own DISA STIG-derived default via ``audit_config.get(key, default)``.
    """

    okta_max_session_idle_minutes: Optional[int] = Field(
        default=None,
        ge=1,
        le=1440,
        description=(
            "Maximum acceptable Global Session idle timeout, in minutes. "
            "Range: 1..1440 (DISA STIG V-273186 recommends 15; raising it "
            "weakens the idle-timeout control)."
        ),
    )
    okta_max_session_lifetime_minutes: Optional[int] = Field(
        default=None,
        ge=1,
        le=43200,
        description=(
            "Maximum acceptable Global Session lifetime, in minutes. "
            "Range: 1..43200 i.e. up to 30 days (DISA STIG recommends 18h = "
            "1080; raising it weakens the session-lifetime control)."
        ),
    )
    okta_admin_console_idle_timeout_max_minutes: Optional[int] = Field(
        default=None,
        ge=1,
        le=1440,
        description=(
            "Maximum acceptable Okta Admin Console app idle timeout, in "
            "minutes. Range: 1..1440 (DISA STIG V-273187 recommends 15)."
        ),
    )
    okta_user_inactivity_max_days: Optional[int] = Field(
        default=None,
        ge=1,
        le=3650,
        description=(
            "Maximum number of days a user can stay inactive before the "
            "inactivity-automation check flags the org. Range: 1..3650 "
            "(defaults to 35)."
        ),
    )
    okta_dod_approved_ca_issuer_patterns: Optional[list[str]] = Field(
        default=None,
        description=(
            "Additional regex patterns matched against a Smart Card IdP "
            "certificate issuer DN to recognise a DOD-approved CA. Extends "
            "the built-in `OU=DoD` / `OU=ECA` patterns."
        ),
    )

    # API rate limiting
    okta_requests_per_second: Annotated[
        Optional[float], AfterValidator(_validate_requests_per_second)
    ] = Field(
        default=None,
        ge=0,
        le=100,
        description=(
            "Maximum aggregate Okta API requests per second. Range: 0 or "
            f"{MIN_REQUESTS_PER_SECOND}..100 (0 disables throttling). Non-zero "
            f"values below {MIN_REQUESTS_PER_SECOND} are rejected to avoid "
            "impractically slow scans."
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
