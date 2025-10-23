from prowler.providers.common.provider import Provider
from prowler.providers.oraclecloud.services.events.events_service import Events

events_client = Events(Provider.get_global_provider())
