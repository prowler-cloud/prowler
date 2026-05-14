from prowler.providers.cloudflare.services.zone.zone_service import Zone
from prowler.providers.common.provider import Provider

zone_client = Zone(Provider.get_global_provider())
