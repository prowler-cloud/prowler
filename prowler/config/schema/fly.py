"""Fly.io provider config schema with safety bounds."""

from typing import Annotated, Optional

from pydantic import AfterValidator, Field

from prowler.config.schema.base import ProviderConfigBase
from prowler.config.schema.validators import validate_port_range


class FlyProviderConfig(ProviderConfigBase):
    """Fly.io provider configuration schema.

    Defines optional configuration parameters for Fly.io security checks:
    which apps are allowed to hold a public IP address, which edge ports may be
    published, which environment variable names are treated as secret-like,
    and the Machines API retry budget.
    """

    public_apps: Optional[list[str]] = Field(
        default=None,
        description="Apps that are expected to serve public traffic and may hold a public IP address.",
    )
    allowed_public_ports: Annotated[
        Optional[list[int]], AfterValidator(validate_port_range)
    ] = Field(
        default=None,
        description="Edge ports a machine service may publish (1..65535). Defaults to HTTP/HTTPS only.",
    )
    secret_env_name_patterns: Optional[list[str]] = Field(
        default=None,
        description="Substrings that mark a machine env variable name as secret-like.",
    )
    max_retries: Optional[int] = Field(
        default=None,
        ge=0,
        le=10,
        description=(
            "Max retries for Fly.io Machines API requests. Range: 0..10 (0 disables retries)."
        ),
    )
