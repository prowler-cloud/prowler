import os
from os import environ
from typing import Union

from colorama import Fore, Style
from github import Auth, Github, GithubIntegration

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.utils.utils import print_boxes
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
from prowler.providers.github.models import (
    GithubAppIdentityInfo,
    GithubIdentityInfo,
    GithubSession,
)


def format_rsa_key(key: str) -> str:
    """
    Format an RSA private key by adding line breaks to the key body.
    This function takes an RSA private key in PEM format as input and formats it by inserting line breaks every 64 characters in the key body. This formatting is necessary for the GitHub SDK Parser to correctly process the key.
    Args:
        key (str): The RSA private key in PEM format as a string. The key should start with "-----BEGIN RSA PRIVATE KEY-----" and end with "-----END RSA PRIVATE KEY-----".
    Returns:
        str: The formatted RSA private key with line breaks added to the key body. If the input key does not have the correct headers, it is returned unchanged.
    Example:
        >>> key = "-----BEGIN RSA PRIVATE KEY-----XXXXXXXXXXXXX...-----END RSA PRIVATE KEY-----"
        >>> formatted_key = format_rsa_key(key)
        >>> print(formatted_key)
        -----BEGIN RSA PRIVATE KEY-----
        XXXXXXXXXXXXX...
        -----END RSA PRIVATE KEY-----

    """
    if (
        key.startswith("-----BEGIN RSA PRIVATE KEY-----")
        and key.endswith("-----END RSA PRIVATE KEY-----")
        and "\n" not in key
    ):
        # Extract the key body (excluding the headers)
        key_body = key[
            len("-----BEGIN RSA PRIVATE KEY-----") : len(key)
            - len("-----END RSA PRIVATE KEY-----")
        ].strip()
        # Add line breaks to the body
        formatted_key_body = "\n".join(
            [key_body[i : i + 64] for i in range(0, len(key_body), 64)]
        )
        # Reconstruct the key with headers and formatted body
        return f"-----BEGIN RSA PRIVATE KEY-----\n{formatted_key_body}\n-----END RSA PRIVATE KEY-----"
    return key


class GithubProvider(Provider):
    """
    GitHub Provider class

    This class is responsible for setting up the GitHub provider, including the session, identity, audit configuration, fixer configuration, and mutelist.

    Attributes:
        _type (str): The type of the provider.
        _auth_method (str): The authentication method used by the provider.
        _session (GithubSession): The session object for the provider.
        _identity (GithubIdentityInfo): The identity information for the provider.
        _audit_config (dict): The audit configuration for the provider.
        _fixer_config (dict): The fixer configuration for the provider.
        _mutelist (Mutelist): The mutelist for the provider.
        audit_metadata (Audit_Metadata): The audit metadata for the provider.
    """

    _type: str = "github"
    _auth_method: str = None
    _session: GithubSession
    _identity: GithubIdentityInfo
    _audit_config: dict
    _mutelist: Mutelist
    audit_metadata: Audit_Metadata

    def __init__(
        self,
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
            personal_access_token (str): GitHub personal access token.
            oauth_app_token (str): GitHub OAuth App token.
            github_app_key (str): GitHub App key.
            github_app_id (int): GitHub App ID.
            config_path (str): Path to the audit configuration file.
            config_content (dict): Audit configuration content.
            fixer_config (dict): Fixer configuration content.
            mutelist_path (str): Path to the mutelist file.
            mutelist_content (dict): Mutelist content.
        """
        logger.info("Instantiating GitHub Provider...")

        self._session = self.setup_session(
            personal_access_token,
            oauth_app_token,
            github_app_id,
            github_app_key,
        )

        self._identity = self.setup_identity()

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
        personal_access_token: str = None,
        oauth_app_token: str = None,
        github_app_id: int = 0,
        github_app_key: str = None,
    ) -> GithubSession:
        """
        Returns the GitHub headers responsible  authenticating API calls.

        Args:
            personal_access_token (str): GitHub personal access token.
            oauth_app_token (str): GitHub OAuth App token.
            github_app_id (int): GitHub App ID.
            github_app_key (str): GitHub App key.

        Returns:
            GithubSession: Authenticated session token for API requests.
        """

        session_token = ""
        app_key = ""
        app_id = 0

        try:
            # Ensure that at least one authentication method is selected. Default to environment variable for PAT if none is provided.
            if personal_access_token:
                session_token = personal_access_token
                self._auth_method = "Personal Access Token"

            elif oauth_app_token:
                session_token = oauth_app_token
                self._auth_method = "OAuth App Token"

            elif github_app_id and github_app_key:
                app_id = github_app_id
                with open(github_app_key, "r") as rsa_key:
                    app_key = rsa_key.read()

                self._auth_method = "GitHub App Token"

            else:
                # PAT
                logger.info(
                    "Looking for GITHUB_PERSONAL_ACCESS_TOKEN environment variable as user has not provided any token...."
                )
                session_token = environ.get("GITHUB_PERSONAL_ACCESS_TOKEN", "")
                if session_token:
                    self._auth_method = "Environment Variable for Personal Access Token"

                if not session_token:
                    # OAUTH
                    logger.info(
                        "Looking for GITHUB_OAUTH_TOKEN environment variable as user has not provided any token...."
                    )
                    session_token = environ.get("GITHUB_OAUTH_APP_TOKEN", "")
                    if session_token:
                        self._auth_method = "Environment Variable for OAuth App Token"

                    if not session_token:
                        # APP
                        logger.info(
                            "Looking for GITHUB_APP_ID and GITHUB_APP_KEY environment variables as user has not provided any token...."
                        )
                        app_id = environ.get("GITHUB_APP_ID", "")
                        app_key = format_rsa_key(environ.get(r"GITHUB_APP_KEY", ""))

                        if app_id and app_key:
                            self._auth_method = (
                                "Environment Variables for GitHub App Key and ID"
                            )

            if not self._auth_method:
                raise GithubEnvironmentVariableError(
                    file=os.path.basename(__file__),
                    message="No authentication method selected and not environment variables were found.",
                )

            credentials = GithubSession(
                token=session_token,
                key=app_key,
                id=app_id,
            )

            return credentials

        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            raise GithubSetUpSessionError(
                original_exception=error,
            )

    def setup_identity(
        self,
    ) -> Union[GithubIdentityInfo, GithubAppIdentityInfo]:
        """
        Returns the GitHub identity information

        Returns:
            GithubIdentityInfo | GithubAppIdentityInfo: An instance of GithubIdentityInfo or GithubAppIdentityInfo containing the identity information.
        """
        credentials = self.session

        try:
            if credentials.token:
                auth = Auth.Token(credentials.token)
                g = Github(auth=auth)
                try:
                    identity = GithubIdentityInfo(
                        account_id=g.get_user().id,
                        account_name=g.get_user().login,
                        account_url=g.get_user().url,
                    )
                    return identity

                except Exception as error:
                    raise GithubInvalidTokenError(
                        original_exception=error,
                    )

            elif credentials.id != 0 and credentials.key:
                auth = Auth.AppAuth(credentials.id, credentials.key)
                gi = GithubIntegration(auth=auth)
                try:
                    identity = GithubAppIdentityInfo(app_id=gi.get_app().id)
                    return identity

                except Exception as error:
                    raise GithubInvalidCredentialsError(
                        original_exception=error,
                    )

        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            raise GithubSetUpIdentityError(
                original_exception=error,
            )

    def print_credentials(self):
        """
        Prints the GitHub credentials.

        Usage:
            >>> self.print_credentials()
        """
        if isinstance(self.identity, GithubIdentityInfo):
            report_lines = [
                f"GitHub Account: {Fore.YELLOW}{self.identity.account_name}{Style.RESET_ALL}",
                f"GitHub Account ID: {Fore.YELLOW}{self.identity.account_id}{Style.RESET_ALL}",
                f"Authentication Method: {Fore.YELLOW}{self.auth_method}{Style.RESET_ALL}",
            ]
        elif isinstance(self.identity, GithubAppIdentityInfo):
            report_lines = [
                f"GitHub App ID: {Fore.YELLOW}{self.identity.app_id}{Style.RESET_ALL}",
                f"Authentication Method: {Fore.YELLOW}{self.auth_method}{Style.RESET_ALL}",
            ]
        report_title = (
            f"{Style.BRIGHT}Using the GitHub credentials below:{Style.RESET_ALL}"
        )
        print_boxes(report_lines, report_title)
