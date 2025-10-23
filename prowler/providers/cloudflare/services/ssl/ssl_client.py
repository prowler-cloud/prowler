from prowler.providers.cloudflare.services.ssl.ssl_service import SSL
from prowler.providers.common.provider import Provider

ssl_client = SSL(Provider.get_global_provider())
