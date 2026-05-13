from typing import Optional

from pydantic import Field

from prowler.config.schema.base import ProviderConfigBase


class CloudflareProviderConfig(ProviderConfigBase):
    # 0 disables retries; negative values would loop or assert in the client.
    max_retries: Optional[int] = Field(default=None, ge=0)
