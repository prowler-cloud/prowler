from typing import Optional

from pydantic import Field

from prowler.config.schema.base import ProviderConfigBase


class M365ProviderConfig(ProviderConfigBase):
    # Entra
    sign_in_frequency: Optional[int] = Field(default=None, gt=0)

    # Teams
    allowed_cloud_storage_services: Optional[list[str]] = None

    # Exchange
    recommended_mailtips_large_audience_threshold: Optional[int] = Field(
        default=None, gt=0
    )

    # Defender malware policy
    default_recommended_extensions: Optional[list[str]] = None

    # Mailbox auditing
    audit_log_age: Optional[int] = Field(default=None, gt=0)
