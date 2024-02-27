from prowler.providers.common.common import get_global_provider
from prowler.providers.gcp.services.apikeys.apikeys_service import APIKeys

apikeys_client = APIKeys(get_global_provider())
