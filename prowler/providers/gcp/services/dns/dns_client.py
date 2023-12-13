from prowler.providers.common.common import global_provider
from prowler.providers.gcp.services.dns.dns_service import DNS

dns_client = DNS(global_provider)
