from prowler.providers.ionos.services.objectstorage.objectstorage_service import IonosObjectStorage
from prowler.providers.common.provider import Provider

ionos_objectstorage_client = IonosObjectStorage(Provider.get_global_provider())