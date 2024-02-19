from prowler.providers.aws.services.networkfirewall.networkfirewall_service import (
    NetworkFirewall,
)
from prowler.providers.common.common import get_global_provider

networkfirewall_client = NetworkFirewall(get_global_provider())
