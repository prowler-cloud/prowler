from mock import MagicMock

from prowler.providers.github.github_provider import GithubProvider
from prowler.providers.github.models import GithubIdentityInfo, GithubSession

# GitHub Identity
ACCOUNT_NAME = "account-name"
ACCOUNT_ID = "account-id"
ACCOUNT_URL = "/user"

# GitHub Credentials
TOKEN = "github-token"


# Mocked GitHub Provider
def set_mocked_github_provider(
    auth_method: str = "personal_access",
    credentials: GithubSession = GithubSession(token=TOKEN),
    identity: GithubIdentityInfo = GithubIdentityInfo(
        account_name=ACCOUNT_NAME,
        account_id=ACCOUNT_ID,
        account_url=ACCOUNT_URL,
    ),
    audit_config: dict = None,
) -> GithubProvider:

    provider = MagicMock()
    provider.type = "github"
    provider.auth_method = auth_method
    provider.session = credentials
    provider.identity = identity
    provider.audit_config = audit_config

    return provider
