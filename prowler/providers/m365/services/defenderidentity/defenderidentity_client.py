from prowler.providers.common.provider import Provider
from prowler.providers.m365.services.defenderidentity.defenderidentity_service import (
    DefenderIdentity,
)

defenderidentity_client = DefenderIdentity(Provider.get_global_provider())
