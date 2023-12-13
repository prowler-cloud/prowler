from prowler.providers.common.common import global_provider
from prowler.providers.gcp.services.apikeys.apikeys_service import APIKeys

apikeys_client = APIKeys(global_provider)
