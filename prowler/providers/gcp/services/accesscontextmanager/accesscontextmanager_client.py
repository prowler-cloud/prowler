from prowler.providers.common.provider import Provider
from prowler.providers.gcp.services.accesscontextmanager.accesscontextmanager_service import (
    AccessContextManager,
)

accesscontextmanager_client = AccessContextManager(Provider.get_global_provider())
