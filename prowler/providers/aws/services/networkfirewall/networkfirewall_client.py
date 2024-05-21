from prowler.providers.aws.services.networkfirewall.networkfirewall_service import (
    NetworkFirewall,
)
from prowler.providers.common.provider import Provider

networkfirewall_client = NetworkFirewall(Provider.get_global_provider())
