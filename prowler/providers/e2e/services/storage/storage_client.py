from prowler.providers.common.provider import Provider
from prowler.providers.e2e.services.storage.storage_service import Storage

storage_client = Storage(Provider.get_global_provider())
