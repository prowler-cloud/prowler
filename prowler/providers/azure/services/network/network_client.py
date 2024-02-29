from prowler.providers.azure.services.network.network_service import Network
from prowler.providers.common.common import get_global_provider

network_client = Network(get_global_provider())
