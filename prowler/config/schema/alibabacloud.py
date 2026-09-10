"""Alibaba Cloud provider config schema with safety bounds."""

from typing import Optional

from pydantic import Field

from prowler.config.schema.base import ProviderConfigBase


class AlibabaCloudProviderConfig(ProviderConfigBase):
    """Alibaba Cloud provider configuration schema.

    Bounds the retention and staleness thresholds consumed by the Alibaba
    Cloud checks. Every field is optional: when omitted (or dropped for being
    out of range) the check falls back to its own default via
    ``audit_config.get(key, default)``.
    """

    max_cluster_check_days: Optional[int] = Field(
        default=None,
        ge=1,
        le=365,
        description=(
            "Maximum number of days an ACK cluster can go without a security "
            "check before being flagged. Range: 1..365 (defaults to 7)."
        ),
    )
    max_console_access_days: Optional[int] = Field(
        default=None,
        ge=30,
        le=180,
        description=(
            "Days a RAM user's console access can stay unused before being "
            "flagged. Range: 30..180 (defaults to 90)."
        ),
    )
    min_log_retention_days: Optional[int] = Field(
        default=None,
        ge=1,
        le=3650,
        description=(
            "Minimum required SLS log store retention, in days. Range: "
            "1..3650 (defaults to 365)."
        ),
    )
    min_rds_audit_retention_days: Optional[int] = Field(
        default=None,
        ge=1,
        le=3650,
        description=(
            "Minimum required RDS SQL audit log retention, in days. Range: "
            "1..3650 (defaults to 180)."
        ),
    )
