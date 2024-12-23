from prowler.providers.common.provider import Provider
from prowler.providers.github.services.organization.organization_service import (
    Organization,
)

organization_client = Organization(Provider.get_global_provider())
