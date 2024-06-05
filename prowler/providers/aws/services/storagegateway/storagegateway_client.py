from prowler.providers.aws.services.storagegateway.storagegateway_service import (
    StorageGateway,
)
from prowler.providers.common.provider import Provider

storagegateway_client = StorageGateway(Provider.get_global_provider())
