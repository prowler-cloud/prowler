from prowler.providers.common.provider import Provider
from prowler.providers.okta.services.network.network_zone_service import NetworkZone

network_zone_client = NetworkZone(Provider.get_global_provider())
