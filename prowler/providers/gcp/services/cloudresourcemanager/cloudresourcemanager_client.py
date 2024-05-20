from prowler.providers.common.provider import Provider
from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
    CloudResourceManager,
)

cloudresourcemanager_client = CloudResourceManager(Provider.get_global_provider())
