from prowler.providers.common.provider import Provider
from prowler.providers.m365.services.defender.defender_service import DefenderIdentity

defender_identity_client = DefenderIdentity(Provider.get_global_provider())
