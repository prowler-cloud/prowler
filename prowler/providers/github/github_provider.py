from os import getenv

from github import Auth, Github

from prowler.config.config import (
    default_config_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.providers.common.models import Audit_Metadata
from prowler.providers.common.provider import Provider
from prowler.providers.github.models import GithubIdentityInfo, GithubSession


class GithubProvider(Provider):
    _type: str = "github"
    _session: GithubSession
    _identity: GithubIdentityInfo
    _audit_config: dict
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        personal_access_token: bool = False,
        github_app: bool = False,
        oauth_app: bool = False,
        config_content: dict = None,
        config_path: str = None,
    ):
        """
        GitHub Provider constructor

        Args:
            personal_access_token (str): GitHub token as authentication method
            github_app (bool): GitHub App as authentication method
            oauth_app (bool): OAuth App as authentication method
            config_content (dict): Configuration content
            config_path (str): Configuration path
        """
        logger.info("Instantiating GitHub Provider...")
        self._session = self.setup_session(
            personal_access_token,
            github_app,
            oauth_app,
        )
        self._identity = self.setup_identity(
            personal_access_token,
            github_app,
            oauth_app,
        )
        self._audit_config = {}
        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

    @property
    def identity(self):
        """Returns the identity information for the GitHub provider."""
        return self._identity

    @property
    def session(self):
        """Returns the session object for the GitHub provider."""
        return self._session

    @property
    def type(self):
        """Returns the type of the GitHub provider."""
        return self._type

    @property
    def audit_config(self):
        """Returns the audit configuration for the GitHub provider."""
        return self._audit_config

    @staticmethod
    def setup_session(
        self,
        personal_access_token: bool = False,
        github_app: bool = False,
        oauth_app: bool = False,
    ) -> GithubSession:
        """
        Returns the GitHub headers responsible  authenticating API calls.

        Args:
            personal_access_token (str): Flag indicating whether to use GitHub personal access token as authentication method.
            github_app (bool): Flag indicating whether to use GitHub App as authentication method.
            oauth_app (bool): Flag indicating whether to use OAuth App as authentication method.

        Returns:
            GithubSession: Authenticated session for API requests.
        """

        if personal_access_token:
            token = getenv("GITHUB_PERSONAL_ACCESS_TOKEN")
        elif github_app:
            token = getenv("GITHUB_APP_TOKEN")
        elif oauth_app:
            token = getenv("GITHUB_OAUTH_TOKEN")
        else:
            raise ValueError(
                "A GitHub API token of some kind is required to initialize GitHub provider."
            )

        credentials = GithubSession(token=Auth.Token(token=token))

        return credentials

    @staticmethod
    def setup_identity(
        self,
        personal_access_token: bool = False,
        github_app: bool = False,
        oauth_app: bool = False,
    ) -> GithubIdentityInfo:
        """
        Returns the GitHub identity information

        Args:
            personal_access_token (str): Flag indicating whether to use GitHub personal access token as authentication method.
            github_app (bool): Flag indicating whether to use GitHub App as authentication method.
            oauth_app (bool): Flag indicating whether to use OAuth App as authentication method.

        Returns:
            GithubIdentityInfo: An instance of GithubIdentityInfo containing the identity information.
        """
        credentials = self.session
        identity = GithubIdentityInfo()

        if personal_access_token or github_app or oauth_app:
            auth = Auth.Token(credentials.token)
            g = Github(auth=auth)
            identity.account_name = g.get_user().login
            identity.account_id = g.get_user().id
            identity.account_url = g.get_user().url

            return identity
