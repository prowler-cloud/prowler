from unittest.mock import patch

from prowler.config.config import (
    default_fixer_config_file_path,
    load_and_validate_config_file,
)
from prowler.providers.github.github_provider import GithubProvider
from prowler.providers.github.models import GithubIdentityInfo, GithubSession
from tests.providers.github.github_fixtures import (
    ACCOUNT_ID,
    ACCOUNT_NAME,
    ACCOUNT_URL,
    TOKEN,
)


class TestGitHubProvider:
    def test_github_provider(self):
        # We need to set exactly one auth method
        personal_access = True
        oauth_app = False
        github_app = False
        fixer_config = load_and_validate_config_file(
            "github", default_fixer_config_file_path
        )

        with patch(
            "prowler.providers.github.github_provider.GithubProvider.setup_session",
            return_value=GithubSession(token=TOKEN),
        ), patch(
            "prowler.providers.github.github_provider.GithubProvider.setup_identity",
            return_value=GithubIdentityInfo(
                account_id=ACCOUNT_ID,
                account_name=ACCOUNT_NAME,
                account_url=ACCOUNT_URL,
            ),
        ):
            provider = GithubProvider(
                personal_access,
                github_app,
                oauth_app,
            )

            assert provider._type == "github"
            assert provider.session == GithubSession(token=TOKEN)
            assert provider.identity == GithubIdentityInfo(
                account_name=ACCOUNT_NAME,
                account_id=ACCOUNT_ID,
                account_url=ACCOUNT_URL,
            )
            assert provider._audit_config == {}
            assert provider._fixer_config == fixer_config
