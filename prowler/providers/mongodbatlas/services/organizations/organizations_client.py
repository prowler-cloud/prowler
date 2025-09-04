from prowler.providers.common.provider import Provider
from prowler.providers.mongodbatlas.services.organizations.organizations_service import (
    Organizations,
)

organizations_client = Organizations(Provider.get_global_provider())
