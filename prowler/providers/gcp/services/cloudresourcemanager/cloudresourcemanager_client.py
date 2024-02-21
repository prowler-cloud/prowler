from prowler.providers.common.common import get_global_provider
from prowler.providers.gcp.services.cloudresourcemanager.cloudresourcemanager_service import (
    CloudResourceManager,
)

cloudresourcemanager_client = CloudResourceManager(get_global_provider())
