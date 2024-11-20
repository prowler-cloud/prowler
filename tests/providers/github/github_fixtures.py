from mock import MagicMock
from prowler.providers.github.github_provider import GithubProvider
from prowler.providers.github.models import GithubIdentityInfo, GithubSession

# GitHub Identity
ACCOUNT_NAME = "account-name"
ACCOUNT_ID = "account-id"
ACCOUNT_URL = "/user"

# Mocked GitHub Provider
def set_mocked_github_provider(
    credentials: 
) -> GithubProvider:
    provider = MagicMock()
    provider.type = "github"
    provider.session = GithubSession()
    provider.identity = GithubIdentityInfo(
        account_name=ACCOUNT_NAME,
        account_id=ACCOUNT_ID,
        account_url=ACCOUNT_URL,
    )
    return provider