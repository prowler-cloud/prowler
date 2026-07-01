"""Okta provider config schema with safety bounds."""

from typing import Optional

from pydantic import Field

from prowler.config.schema.base import ProviderConfigBase


class OktaProviderConfig(ProviderConfigBase):
    """Okta provider configuration schema.

    Bounds the session, idle-timeout and inactivity thresholds consumed by
    the Okta checks. Every field is optional: when omitted (or dropped for
    being out of range) the check falls back to its own DISA STIG-derived
    default via ``audit_config.get(key, default)``.
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
