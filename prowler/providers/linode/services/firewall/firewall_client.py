from prowler.providers.common.provider import Provider
from prowler.providers.linode.services.firewall.firewall_service import FirewallService

firewall_client = FirewallService(Provider.get_global_provider())
