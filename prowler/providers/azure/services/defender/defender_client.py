from prowler.providers.azure.services.defender.defender_service import Defender
from prowler.providers.common.common import get_global_provider

defender_client = Defender(get_global_provider())
