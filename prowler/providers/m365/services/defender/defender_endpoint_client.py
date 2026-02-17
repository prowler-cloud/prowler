from prowler.providers.common.provider import Provider
from prowler.providers.m365.services.defender.defender_service import DefenderEndpoint

defender_endpoint_client = DefenderEndpoint(Provider.get_global_provider())
