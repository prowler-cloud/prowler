from prowler.providers.cloudflare.services.dns.dns_service import DNS
from prowler.providers.common.provider import Provider

dns_client = DNS(Provider.get_global_provider())
