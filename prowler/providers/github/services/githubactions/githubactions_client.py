from prowler.providers.common.provider import Provider
from prowler.providers.github.services.githubactions.githubactions_service import (
    GithubActions,
)

githubactions_client = GithubActions(Provider.get_global_provider())
