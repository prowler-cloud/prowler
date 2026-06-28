"""GCP provider config schema with safety bounds."""

from typing import Optional

from pydantic import Field

from prowler.config.schema.base import ProviderConfigBase


class GCPProviderConfig(ProviderConfigBase):
    shodan_api_key: Optional[str] = Field(
        default=None,
        max_length=512,
        description="API key for Shodan lookups on GCP public IPs.",
    )
    mig_min_zones: Optional[int] = Field(
        default=None,
        ge=1,
        le=5,
        description="Min zones a Managed Instance Group must span. Range: 1..5.",
    )
    max_snapshot_age_days: Optional[int] = Field(
        default=None,
        ge=1,
        le=1095,
        description=(
            "Days a disk snapshot can age before being flagged. Range: 1..1095 "
            "(3 years; older snapshots typically miss data-class compliance)."
        ),
    )
    max_unused_account_days: Optional[int] = Field(
        default=None,
        ge=30,
        le=365,
        description=(
            "Days a service account or user-managed key can stay unused. "
            "Range: 30..365."
        ),
    )
    storage_min_retention_days: Optional[int] = Field(
        default=None,
        ge=1,
        le=3650,
        description="Min retention period on Cloud Storage buckets. Range: 1..3650.",
    )
