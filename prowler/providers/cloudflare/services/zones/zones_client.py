from prowler.providers.cloudflare.services.zones.zones_service import Zones
from prowler.providers.common.provider import Provider

zones_client = Zones(Provider.get_global_provider())
