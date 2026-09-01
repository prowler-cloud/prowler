"""Fly.io provider config schema with safety bounds."""

from typing import Optional

from pydantic import Field

from prowler.config.schema.base import ProviderConfigBase


class FlyProviderConfig(ProviderConfigBase):
    """Fly.io provider configuration schema.

    Defines optional configuration parameters for Fly.io security checks:
    which apps are allowed to hold a public IP address, which edge ports may be
    published, and which environment variable names are treated as secret-like.
    """

    public_apps: Optional[list[str]] = Field(
        default=None,
        description="Apps that are expected to serve public traffic and may hold a public IP address.",
    )
    allowed_public_ports: Optional[list[int]] = Field(
        default=None,
        description="Edge ports a machine service may publish. Defaults to HTTP/HTTPS only.",
    )
    secret_env_name_patterns: Optional[list[str]] = Field(
        default=None,
        description="Substrings that mark a machine env variable name as secret-like.",
    )
