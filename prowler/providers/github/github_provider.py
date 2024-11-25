import os
from os import getenv

from github import Auth, Github, GithubIntegration

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.providers.common.models import Audit_Metadata
from prowler.providers.common.provider import Provider
from prowler.providers.github.exceptions.exceptions import (
    GithubEnvironmentVariableError,
    GithubInvalidCredentialsError,
    GithubInvalidTokenError,
    GithubSetUpIdentityError,
    GithubSetUpSessionError,
)
from prowler.providers.github.lib.mutelist.mutelist import GithubMutelist
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
        # Env Vars Authentication methods
        personal_access: bool = False,
        oauth_app: bool = False,
        github_app: bool = False,
        # Authentication credentials
        personal_access_token: str = "",
        oauth_app_token: str = "",
        github_app_key: str = "",
        github_app_id: int = 0,
        # Provider configuration
        config_path: str = None,
        config_content: dict = None,
        fixer_config: dict = {},
        mutelist_path: str = None,
        mutelist_content: dict = None,
    ):
        """
        GitHub Provider constructor

        Args:
            personal_access (str): GitHub token as authentication method
            github_app (bool): GitHub App as authentication method
            oauth_app (bool): OAuth App as authentication method
            config_content (dict): Configuration content
            config_path (str): Configuration path
        """
        logger.info("Instantiating GitHub Provider...")

        self._session = self.setup_session(
            personal_access,
            oauth_app,
            github_app,
            personal_access_token,
            oauth_app_token,
            github_app_key,
            github_app_id,
        )

        self._identity = self.setup_identity(
            personal_access,
            oauth_app,
            github_app,
            personal_access_token,
            oauth_app_token,
            github_app_key,
            github_app_id,
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
            self._mutelist = GithubMutelist(
                mutelist_content=mutelist_content,
            )
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = GithubMutelist(
                mutelist_path=mutelist_path,
            )
        Provider.set_global_provider(self)

    @property
    def auth_method(self):
        """Returns the authentication method for the GitHub provider."""
        return self._auth_method

    @property
    def pat(self):
        """Returns the personal access token for the GitHub provider."""
        return self._pat

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
    def mutelist(self) -> GithubMutelist:
        """
        mutelist method returns the provider's mutelist.
        """
        return self._mutelist

    def setup_session(
        self,
        personal_access: bool,
        oauth_app: bool = False,
        github_app: bool = False,
        personal_access_token: str = None,
        oauth_app_token: str = None,
        github_app_key: str = None,
        github_app_id: int = 0,
    ) -> GithubSession:
        """
        Returns the GitHub headers responsible  authenticating API calls.

        Args:
            personal_access (str): Flag indicating whether to use GitHub personal access token as authentication method.
            github_app (bool): Flag indicating whether to use GitHub App as authentication method.
            oauth_app (bool): Flag indicating whether to use OAuth App as authentication method.

        Returns:
            GithubSession: Authenticated session token for API requests.
        """

        session_token = ""
        app_key = ""
        app_id = 0

        try:
            # Ensure that at least one authentication method is selected. Default to environment variable for PAT if none is provided.
            if (
                not personal_access
                and not oauth_app
                and not github_app
                and not personal_access_token
                and not oauth_app_token
                and not github_app_key
            ):
                logger.error(
                    "GitHub provider: No authentication method selected. Prowler will try to use GITHUB_PERSONAL_ACCESS_TOKEN enviroment variable to log in by default."
                )
                personal_access = True

            if personal_access_token:
                session_token = personal_access_token
                self._auth_method = "Enviroment Variable for Personal Access Token"

            elif personal_access:
                if not getenv("GITHUB_PERSONAL_ACCESS_TOKEN"):
                    logger.critical(
                        "GitHub provider: Missing enviroment variable GITHUB_PERSONAL_ACCESS_TOKEN needed to authenticate against GitHub."
                    )
                    raise GithubEnvironmentVariableError(
                        file=os.path.basename(__file__),
                        message="Missing Github environment variable GITHUB_PERSONAL_ACCESS_TOKEN required to authenticate.",
                    )
                session_token = getenv("GITHUB_PERSONAL_ACCESS_TOKEN")
                self._auth_method = "Personal Access Token"

            elif oauth_app_token:
                session_token = oauth_app_token
                self._auth_method = "OAuth App token"

            elif oauth_app:
                if not getenv("GITHUB_OAUTH_APP_TOKEN"):
                    logger.critical(
                        "GitHub provider: Missing enviroment variable GITHUB_OAUTH_APP_TOKEN needed to authenticate against GitHub."
                    )
                    raise GithubEnvironmentVariableError(
                        file=os.path.basename(__file__),
                        message="Missing Github environment variable GITHUB_OAUTH_APP_TOKEN required to authenticate.",
                    )
                self._auth_method = "Enviroment Variable for OAuth App Token"

            elif github_app_key and github_app_id:
                app_key = github_app_key
                app_id = github_app_id
                self._auth_method = "GitHub App Token"

            elif github_app:
                if not getenv("github_app_key"):
                    logger.critical(
                        "GitHub provider: Missing enviroment variable github_app_key needed to authenticate against GitHub."
                    )
                    raise GithubEnvironmentVariableError(
                        file=os.path.basename(__file__),
                        message="Missing Github environment variable github_app_key required to authenticate.",
                    )
                session_token = getenv("github_app_key")
                self._auth_method = "Enviroment Variable for GitHub App Token"

            else:
                logger.critical(
                    "GitHub provider: A Github token is required to authenticate against Github."
                )

            credentials = GithubSession(
                token=session_token,
                key=app_key,
                id=app_id,
            )

            return credentials

        except Exception as error:
            logger.critical("GitHub provider: Error setting up session.")
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            raise GithubSetUpSessionError(
                original_exception=error,
            )

    def setup_identity(
        self,
        personal_access,
        oauth_app,
        github_app,
        personal_access_token,
        oauth_app_token,
        github_app_key,
        github_app_id: int = 0,
    ) -> GithubIdentityInfo:
        """
        Returns the GitHub identity information

        Args:
            personal_access (str): Flag indicating whether to use GitHub personal access token as authentication method.
            github_app (bool): Flag indicating whether to use GitHub App as authentication method.
            oauth_app (bool): Flag indicating whether to use OAuth App as authentication method.

        Returns:
            GithubIdentityInfo: An instance of GithubIdentityInfo containing the identity information.
        """
        credentials = self.session

        try:
            if (
                (personal_access or personal_access_token)
                or (oauth_app or oauth_app_token)
                or (
                    not personal_access
                    and not github_app
                    and not oauth_app
                    and not oauth_app_token
                )
            ):
                auth = Auth.Token(credentials.token)
                g = Github(auth=auth)

                try:
                    identity = GithubIdentityInfo(
                        account_name=g.get_user().login,
                        account_id=g.get_user().id,
                        account_url=g.get_user().url,
                    )
                    return identity

                except Exception as error:
                    logger.critical("GitHub provider: Given token is not valid.")
                    raise GithubInvalidTokenError(
                        original_exception=error,
                    )

            elif github_app_key and github_app_id:
                auth = Auth.AppAuth(credentials.key, credentials.id)
                gi = GithubIntegration(auth=auth)

                try:
                    identity = GithubIdentityInfo(
                        account_name=gi.get_user().login,
                        account_id=gi.get_user().id,
                        account_url=gi.get_user().url,
                    )
                    return identity

                except Exception as error:
                    logger.critical("GitHub provider: Given token is not valid.")
                    raise GithubInvalidCredentialsError(
                        original_exception=error,
                    )

        except Exception as error:
            logger.critical("GitHub provider: Error setting up identity.")
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            raise GithubSetUpIdentityError(
                original_exception=error,
            )

    def print_credentials(self):
        print(f"You are using a {self.auth_method} as authentication method.")
