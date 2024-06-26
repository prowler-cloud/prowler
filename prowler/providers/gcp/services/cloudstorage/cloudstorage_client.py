from prowler.providers.common.provider import Provider
from prowler.providers.gcp.services.cloudstorage.cloudstorage_service import (
    CloudStorage,
)

cloudstorage_client = CloudStorage(Provider.get_global_provider())
