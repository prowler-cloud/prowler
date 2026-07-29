"""E2E Networks provider config schema."""

from typing import Optional

from pydantic import Field

from prowler.config.schema.base import ProviderConfigBase


class E2eNetworksProviderConfig(ProviderConfigBase):
    """E2E Networks provider configuration schema.

    Defines optional configuration parameters for E2E Networks security checks.
    """

    require_bitninja_on_load_balancers: Optional[bool] = Field(
        default=None,
        description=(
            "Whether BitNinja protection is required on load balancers for the "
            "loadbalancer_bitninja_enabled check."
        ),
    )
