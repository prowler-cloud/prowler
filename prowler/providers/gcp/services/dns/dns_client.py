from prowler.providers.common.common import get_global_provider
from prowler.providers.gcp.services.dns.dns_service import DNS

dns_client = DNS(get_global_provider())
