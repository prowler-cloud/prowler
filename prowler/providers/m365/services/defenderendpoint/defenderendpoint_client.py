from prowler.providers.common.provider import Provider
from prowler.providers.m365.services.defenderendpoint.defenderendpoint_service import (
    DefenderEndpoint,
)

defenderendpoint_client = DefenderEndpoint(Provider.get_global_provider())
