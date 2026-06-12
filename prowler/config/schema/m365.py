"""M365 provider config schema with safety bounds."""

from typing import Optional

from pydantic import Field

from prowler.config.schema.base import ProviderConfigBase


class M365ProviderConfig(ProviderConfigBase):
    # --- Entra (sign-in policy) ----------------------------------------
    sign_in_frequency: Optional[int] = Field(
        default=None,
        ge=1,
        le=168,
        description=(
            "Hours between forced sign-ins for admin users. Range: 1..168 (1 h .. 7 days). "
            "Microsoft Conditional Access baseline for admin roles is ≤24 h."
        ),
    )

    # --- Teams ---------------------------------------------------------
    allowed_cloud_storage_services: Optional[list[str]] = Field(
        default=None,
        description="External cloud storage services allowed in Teams.",
    )

    # --- Exchange ------------------------------------------------------
    recommended_mailtips_large_audience_threshold: Optional[int] = Field(
        default=None,
        ge=5,
        le=10000,
        description=(
            "Recipient count that should trigger a 'large audience' MailTip. "
            "Range: 5..10000 (Microsoft default 25)."
        ),
    )

    # --- Defender malware policy --------------------------------------
    default_recommended_extensions: Optional[list[str]] = Field(
        default=None,
        description="File extensions blocked by the malware policy.",
    )

    # --- Mailbox auditing ---------------------------------------------
    audit_log_age: Optional[int] = Field(
        default=None,
        ge=30,
        le=3650,
        description=(
            "Days mailbox audit logs must be retained. Range: 30..3650 "
            "(M365 E3 default is 90 days; SEC/FINRA require ≥7 years)."
        ),
    )
