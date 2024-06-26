from prowler.providers.azure.services.defender.defender_service import Defender
from prowler.providers.common.provider import Provider

defender_client = Defender(Provider.get_global_provider())
