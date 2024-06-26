from prowler.providers.common.provider import Provider
from prowler.providers.gcp.services.dns.dns_service import DNS

dns_client = DNS(Provider.get_global_provider())
