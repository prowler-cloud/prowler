from os import getenv

from github import Auth, Github

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.providers.common.models import Audit_Metadata
from prowler.providers.common.provider import Provider
from prowler.providers.github.lib.mutelist.mutelist import GitHubMutelist
from prowler.providers.github.models import GithubIdentityInfo, GithubSession


class GithubProvider(Provider):
    _type: str = "github"
    _auth_method: str
    _session: GithubSession
    _identity: GithubIdentityInfo
    _audit_config: dict
    _mutelist: Mutelist
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        personal_access_token: bool = False,
        github_app: bool = False,
        oauth_app: bool = False,
        config_path: str = None,
        config_content: dict = None,
        fixer_config: dict = {},
        mutelist_path: str = None,
        mutelist_content: dict = None,
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

        # Audit Config
        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

        # Fixer Config
        self._fixer_config = fixer_config

        # Mutelist
        if mutelist_content:
            self._mutelist = GitHubMutelist(
                mutelist_content=mutelist_content,
            )
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = GitHubMutelist(
                mutelist_path=mutelist_path,
            )
        Provider.set_global_provider(self)

    @property
    def auth_method(self):
        """Returns the authentication method for the GitHub provider."""
        return self._auth_method

    @property
    def session(self):
        """Returns the session object for the GitHub provider."""
        return self._session

    @property
    def identity(self):
        """Returns the identity information for the GitHub provider."""
        return self._identity

    @property
    def type(self):
        """Returns the type of the GitHub provider."""
        return self._type

    @property
    def audit_config(self):
        return self._audit_config

    @property
    def fixer_config(self):
        return self._fixer_config

    @property
    def mutelist(self) -> GitHubMutelist:
        """
        mutelist method returns the provider's mutelist.
        """
        return self._mutelist

    def setup_session(
        self,
        personal_access_token: bool,
        github_app: bool,
        oauth_app: bool,
    ) -> GithubSession:
        """
        Returns the GitHub headers responsible  authenticating API calls.

        Args:
            personal_access_token (str): Flag indicating whether to use GitHub personal access token as authentication method.
            github_app (bool): Flag indicating whether to use GitHub App as authentication method.
            oauth_app (bool): Flag indicating whether to use OAuth App as authentication method.

        Returns:
            GithubSession: Authenticated session token for API requests.
        """

        if personal_access_token:
            session_token = getenv("GITHUB_PERSONAL_ACCESS_TOKEN")
            self._auth_method = "personal_access_token"
        elif github_app:
            session_token = getenv("GITHUB_APP_TOKEN")
            self._auth_method = "github_app"
        elif oauth_app:
            session_token = getenv("GITHUB_OAUTH_TOKEN")
            self._auth_method = "oauth_app"
        else:
            raise ValueError(
                "A GitHub API token of some kind is required to initialize GitHub provider."
            )

        credentials = GithubSession(token=session_token)

        return credentials

    def setup_identity(
        self,
        personal_access_token: bool,
        github_app: bool,
        oauth_app: bool,
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

        if personal_access_token or github_app or oauth_app:
            auth = Auth.Token(credentials.token)
            g = Github(auth=auth)

            identity = GithubIdentityInfo(
                account_name=g.get_user().login,
                account_id=g.get_user().id,
                account_url=g.get_user().url,
            )

            return identity

    def print_credentials(self):
        print(f"You are using a {self.auth_method} as authentication method.")
