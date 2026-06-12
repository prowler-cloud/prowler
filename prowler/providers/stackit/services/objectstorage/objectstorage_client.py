from prowler.providers.common.provider import Provider
from prowler.providers.stackit.services.objectstorage.objectstorage_service import (
    ObjectStorageService,
)

objectstorage_client = ObjectStorageService(Provider.get_global_provider())
