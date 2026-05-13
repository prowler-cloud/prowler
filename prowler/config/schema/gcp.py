from typing import Optional

from pydantic import Field

from prowler.config.schema.base import ProviderConfigBase


class GCPProviderConfig(ProviderConfigBase):
    shodan_api_key: Optional[str] = None
    mig_min_zones: Optional[int] = Field(default=None, gt=0)
    max_snapshot_age_days: Optional[int] = Field(default=None, gt=0)
    max_unused_account_days: Optional[int] = Field(default=None, gt=0)
    storage_min_retention_days: Optional[int] = Field(default=None, gt=0)
