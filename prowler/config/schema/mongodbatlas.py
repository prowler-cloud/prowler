"""MongoDB Atlas provider config schema with safety bounds."""

from typing import Optional

from pydantic import Field

from prowler.config.schema.base import ProviderConfigBase


class MongoDBAtlasProviderConfig(ProviderConfigBase):
    """MongoDB Atlas provider configuration schema.

    Defines optional configuration parameters for MongoDB Atlas security checks,
    including service account secret validity constraints.
    """

    max_service_account_secret_validity_hours: Optional[int] = Field(
        default=None,
        ge=1,
        le=720,
        description=(
            "Max hours a service account secret can stay valid. "
            "Range: 1..720 (1 h .. 30 days)."
        ),
    )
