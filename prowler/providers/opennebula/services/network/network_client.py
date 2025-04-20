from prowler.providers.opennebula.services.network.network_service import NetworkService
from prowler.providers.common.provider import Provider

network_client = NetworkService(Provider.get_global_provider())