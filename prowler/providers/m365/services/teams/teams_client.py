from prowler.providers.common.provider import Provider
from prowler.providers.m365.services.teams.teams_service import Teams

teams_client = Teams(Provider.get_global_provider())
