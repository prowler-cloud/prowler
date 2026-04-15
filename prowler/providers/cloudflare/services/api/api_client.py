from prowler.providers.cloudflare.services.api.api_service import API
from prowler.providers.common.provider import Provider

api_client = API(Provider.get_global_provider())
