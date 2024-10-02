from prowler.providers.azure.services.containerregistry.containerregistry_service import (
    ContainerRegistry,
)
from prowler.providers.common.provider import Provider

containerregistry_client = ContainerRegistry(Provider.get_global_provider())
