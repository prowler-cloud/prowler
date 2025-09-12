from prowler.providers.common.provider import Provider
from prowler.providers.nhn.services.network.network_service import NHNNetworkService

network_client = NHNNetworkService(Provider.get_global_provider())
