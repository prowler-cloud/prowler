from prowler.providers.azure.services.storage.storage_service import Storage
from prowler.providers.common.common import get_global_provider

storage_client = Storage(get_global_provider())
