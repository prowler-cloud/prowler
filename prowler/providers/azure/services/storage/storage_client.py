from prowler.providers.azure.services.storage.storage_service import Storage
from prowler.providers.common.provider import Provider

storage_client = Storage(Provider.get_global_provider())
