from prowler.providers.common.common import get_global_provider
from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
    CloudStorage,
)

cloudstorage_client = CloudStorage(get_global_provider())
