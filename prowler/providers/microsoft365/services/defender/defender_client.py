from prowler.providers.common.provider import Provider
from prowler.providers.microsoft365.services.defender.defender_service import Defender

defender_client = Defender(Provider.get_global_provider())
