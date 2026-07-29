"""GitHub provider config schema with safety bounds."""

from typing import Optional

from pydantic import Field

from prowler.config.schema.base import ProviderConfigBase


class GitHubProviderConfig(ProviderConfigBase):
    inactive_not_archived_days_threshold: Optional[int] = Field(
        default=None,
        ge=30,
        le=3650,
        description=(
            "Days a repository can stay inactive without being archived before "
            "being flagged. Range: 30..3650 (CIS GitHub recommends 180; "
            "<30 days produces false positives on seasonal projects)."
        ),
    )
