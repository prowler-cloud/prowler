from typing import Optional

from pydantic import Field

from prowler.config.schema.base import ProviderConfigBase


class GitHubProviderConfig(ProviderConfigBase):
    inactive_not_archived_days_threshold: Optional[int] = Field(default=None, gt=0)
