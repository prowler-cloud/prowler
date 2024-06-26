from prowler.providers.common.provider import Provider
from prowler.providers.gcp.services.apikeys.apikeys_service import APIKeys

apikeys_client = APIKeys(Provider.get_global_provider())
