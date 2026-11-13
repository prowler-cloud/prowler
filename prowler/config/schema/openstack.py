"""OpenStack provider config schema with safety bounds."""

from typing import Literal, Optional

from pydantic import Field

from prowler.config.schema.base import ProviderConfigBase


class OpenStackProviderConfig(ProviderConfigBase):
    """OpenStack provider configuration schema.

    Bounds the image-sharing threshold and reuses the ``secrets_ignore_patterns``
    config consumed by the metadata sensitive-data checks. Every field is
    optional: when omitted (or dropped for being out of range) the check falls
    back to its own default via ``audit_config.get(key, default)``.
    """

    image_sharing_threshold: Optional[int] = Field(
        default=None,
        ge=1,
        le=1000,
        description=(
            "Maximum number of accepted project members a shared image may "
            "have before being flagged. Range: 1..1000 (defaults to 5)."
        ),
    )
    secrets_ignore_patterns: Optional[list[str]] = Field(
        default=None,
        description=(
            "Regex patterns whose matches are excluded from secret "
            "scanning of resource metadata."
        ),
    )
    secrets_validate: Optional[bool] = Field(
        default=None,
        description=(
            "Validate discovered secrets against the provider APIs (live check). "
            "Makes outbound network calls that authenticate with the discovered "
            "secret. Disabled by default."
        ),
    )
    secrets_confidence: Optional[Literal["low", "medium", "high"]] = Field(
        default=None,
        description=(
            "Minimum Kingfisher confidence level for reporting secret findings. "
            "Possible values: low, medium, high. Default: low."
        ),
    )
