from mock import MagicMock

from prowler.providers.github.github_provider import GithubProvider
from prowler.providers.github.models import GithubIdentityInfo, GithubSession

# GitHub Identity
ACCOUNT_NAME = "account-name"
ACCOUNT_ID = "account-id"
ACCOUNT_URL = "/user"

# GitHub Credentials
PAT_TOKEN = "github-token"
OAUTH_TOKEN = "oauth-token"
APP_ID = "app-id"
APP_KEY = "app-key"


# Mocked GitHub Provider
def set_mocked_github_provider(
    auth_method: str = "personal_access",
    credentials: GithubSession = GithubSession(token=PAT_TOKEN, id=APP_ID, key=APP_KEY),
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
