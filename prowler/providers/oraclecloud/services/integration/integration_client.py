"""OCI Integration client."""

from prowler.providers.common.provider import Provider
from prowler.providers.oraclecloud.services.integration.integration_service import (
    Integration,
)

integration_client = Integration(Provider.get_global_provider())
