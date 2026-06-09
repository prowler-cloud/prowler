"""Vercel provider config schema with safety bounds."""

from typing import Optional

from pydantic import Field

from prowler.config.schema.base import ProviderConfigBase


class VercelProviderConfig(ProviderConfigBase):
    stable_branches: Optional[list[str]] = Field(
        default=None,
        description="Branches considered stable for production deployments.",
    )
    days_to_expire_threshold: Optional[int] = Field(
        default=None,
        ge=7,
        le=365,
        description=(
            "Days before token/certificate expiration to flag. Range: 7..365 "
            "(PCI-DSS 4.2.1.1: alert ≥30 days before expiry)."
        ),
    )
    stale_token_threshold_days: Optional[int] = Field(
        default=None,
        ge=30,
        le=3650,
        description=(
            "Days of inactivity before a token is considered stale. Range: 30..3650 "
            "(NIST AC-2(3) typical window 30..90 days)."
        ),
    )
    stale_invitation_threshold_days: Optional[int] = Field(
        default=None,
        ge=7,
        le=365,
        description=(
            "Days a pending invitation can stay open. Range: 7..365 "
            "(OWASP ASVS 2.7.1 recommends short-lived invitations)."
        ),
    )
    max_owner_percentage: Optional[int] = Field(
        default=None,
        ge=1,
        le=50,
        description=(
            "Max percentage of team members that can have the OWNER role. "
            "Range: 1..50 (PoLP — having >50% of a team as OWNER defeats RBAC; "
            "industry guidance recommends ≤25%)."
        ),
    )
    max_owners: Optional[int] = Field(
        default=None,
        ge=1,
        le=1000,
        description="Absolute max owners (overrides percentage for large teams). Range: 1..1000.",
    )
    secret_suffixes: Optional[list[str]] = Field(
        default=None,
        description="Suffixes that mark a project env var as secret-like.",
    )
