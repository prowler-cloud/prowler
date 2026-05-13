from typing import Optional

from pydantic import Field

from prowler.config.schema.base import ProviderConfigBase


class MongoDBAtlasProviderConfig(ProviderConfigBase):
    max_service_account_secret_validity_hours: Optional[int] = Field(default=None, gt=0)
