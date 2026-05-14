from prowler.providers.common.provider import Provider
from prowler.providers.vercel.services.team.team_service import Team

team_client = Team(Provider.get_global_provider())
