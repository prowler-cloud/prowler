from unittest.mock import patch

from prowler.config.config import (
    default_fixer_config_file_path,
    load_and_validate_config_file,
)
from prowler.providers.github.github_provider import GithubProvider
from prowler.providers.github.models import (
    GithubAppIdentityInfo,
    GithubIdentityInfo,
    GithubSession,
)
from tests.providers.github.github_fixtures import (
    ACCOUNT_ID,
    ACCOUNT_NAME,
    ACCOUNT_URL,
    APP_ID,
    APP_KEY,
    OAUTH_TOKEN,
    PAT_TOKEN,
)


class TestGitHubProvider:
    def test_github_provider_PAT(self):
        personal_access_token = PAT_TOKEN
        oauth_app_token = None
        github_app_id = None
        github_app_key = None
        fixer_config = load_and_validate_config_file(
            "github", default_fixer_config_file_path
        )

        with (
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_session",
                return_value=GithubSession(token=PAT_TOKEN, id="", key=""),
            ),
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_identity",
                return_value=GithubIdentityInfo(
                    account_id=ACCOUNT_ID,
                    account_name=ACCOUNT_NAME,
                    account_url=ACCOUNT_URL,
                ),
            ),
        ):
            provider = GithubProvider(
                personal_access_token,
                oauth_app_token,
                github_app_id,
                github_app_key,
            )

            assert provider._type == "github"
            assert provider.session == GithubSession(token=PAT_TOKEN, id="", key="")
            assert provider.identity == GithubIdentityInfo(
                account_name=ACCOUNT_NAME,
                account_id=ACCOUNT_ID,
                account_url=ACCOUNT_URL,
            )
            assert provider._audit_config == {}
            assert provider._fixer_config == fixer_config

    def test_github_provider_OAuth(self):
        personal_access_token = None
        oauth_app_token = OAUTH_TOKEN
        github_app_id = None
        github_app_key = None
        fixer_config = load_and_validate_config_file(
            "github", default_fixer_config_file_path
        )

        with (
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_session",
                return_value=GithubSession(token=OAUTH_TOKEN, id="", key=""),
            ),
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_identity",
                return_value=GithubIdentityInfo(
                    account_id=ACCOUNT_ID,
                    account_name=ACCOUNT_NAME,
                    account_url=ACCOUNT_URL,
                ),
            ),
        ):
            provider = GithubProvider(
                personal_access_token,
                oauth_app_token,
                github_app_id,
                github_app_key,
            )

            assert provider._type == "github"
            assert provider.session == GithubSession(token=OAUTH_TOKEN, id="", key="")
            assert provider.identity == GithubIdentityInfo(
                account_name=ACCOUNT_NAME,
                account_id=ACCOUNT_ID,
                account_url=ACCOUNT_URL,
            )
            assert provider._audit_config == {}
            assert provider._fixer_config == fixer_config

    def test_github_provider_App(self):
        personal_access_token = None
        oauth_app_token = None
        github_app_id = APP_ID
        github_app_key = APP_KEY
        fixer_config = load_and_validate_config_file(
            "github", default_fixer_config_file_path
        )

        with (
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_session",
                return_value=GithubSession(token="", id=APP_ID, key=APP_KEY),
            ),
            patch(
                "prowler.providers.github.github_provider.GithubProvider.setup_identity",
                return_value=GithubAppIdentityInfo(
                    app_id=APP_ID,
                ),
            ),
        ):
            provider = GithubProvider(
                personal_access_token,
                oauth_app_token,
                github_app_id,
                github_app_key,
            )

            assert provider._type == "github"
            assert provider.session == GithubSession(token="", id=APP_ID, key=APP_KEY)
            assert provider.identity == GithubAppIdentityInfo(app_id=APP_ID)
            assert provider._audit_config == {}
            assert provider._fixer_config == fixer_config
