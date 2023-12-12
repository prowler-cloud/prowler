from prowler.providers.common.common import global_provider
from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
    CloudStorage,
)

cloudstorage_client = CloudStorage(global_provider)
