from prowler.providers.common.provider import Provider
from prowler.providers.m365.services.defenderxdr.defenderxdr_service import DefenderXDR

defenderxdr_client = DefenderXDR(Provider.get_global_provider())
