from typing import Optional

from pydantic import Field

from prowler.config.schema.base import ProviderConfigBase


class VercelProviderConfig(ProviderConfigBase):
    stable_branches: Optional[list[str]] = None
    days_to_expire_threshold: Optional[int] = Field(default=None, gt=0)
    stale_token_threshold_days: Optional[int] = Field(default=None, gt=0)
    stale_invitation_threshold_days: Optional[int] = Field(default=None, gt=0)
    max_owner_percentage: Optional[int] = Field(default=None, ge=0, le=100)
    max_owners: Optional[int] = Field(default=None, gt=0)
    secret_suffixes: Optional[list[str]] = None
