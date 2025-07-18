import os
from os import environ
from typing import Union

from colorama import Fore, Style
from github import Auth, Github, GithubIntegration
from github.GithubRetry import GithubRetry

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider
from prowler.providers.github.exceptions.exceptions import (
    GithubEnvironmentVariableError,
    GithubInvalidCredentialsError,
    GithubInvalidProviderIdError,
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
        _repositories (list): List of repository names to scan in 'owner/repo-name' format.
        _organizations (list): List of organization or user names to scan repositories for.
        audit_metadata (Audit_Metadata): The audit metadata for the provider.
    """

    _type: str = "github"
    _auth_method: str = None
    _session: GithubSession
    _identity: GithubIdentityInfo
    _audit_config: dict
    _mutelist: Mutelist
    _repositories: list
    _organizations: list
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
        # Repository scoping
        repositories: list = None,
        organizations: list = None,
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
            repositories (list): List of repository names to scan in 'owner/repo-name' format.
            organizations (list): List of organization or user names to scan repositories for.
        """
        logger.info("Instantiating GitHub Provider...")

        # Set repositories and organizations for scoping
        self._repositories = repositories or []
        self._organizations = organizations or []

        self._session = GithubProvider.setup_session(
            personal_access_token,
            oauth_app_token,
            github_app_id,
            github_app_key,
        )

        # Set the authentication method
        if personal_access_token:
            self._auth_method = "Personal Access Token"
        elif oauth_app_token:
            self._auth_method = "OAuth App Token"
        elif github_app_id and github_app_key:
            self._auth_method = "GitHub App Token"
        elif environ.get("GITHUB_PERSONAL_ACCESS_TOKEN", ""):
            self._auth_method = "Environment Variable for Personal Access Token"
        elif environ.get("GITHUB_OAUTH_APP_TOKEN", ""):
            self._auth_method = "Environment Variable for OAuth App Token"
        elif environ.get("GITHUB_APP_ID", "") and environ.get("GITHUB_APP_KEY", ""):
            self._auth_method = "Environment Variables for GitHub App Key and ID"

        self._identity = GithubProvider.setup_identity(self._session)

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

    @property
    def repositories(self) -> list:
        """
        repositories method returns the provider's repository list for scoping.
        """
        return self._repositories

    @property
    def organizations(self) -> list:
        """
        organizations method returns the provider's organization list for scoping.
        """
        return self._organizations

    @staticmethod
    def setup_session(
        personal_access_token: str = None,
        oauth_app_token: str = None,
        github_app_id: int = 0,
        github_app_key: str = None,
        github_app_key_content: str = None,
    ) -> GithubSession:
        """
        Returns the GitHub headers responsible  authenticating API calls.

        Args:
            personal_access_token (str): GitHub personal access token.
            oauth_app_token (str): GitHub OAuth App token.
            github_app_id (int): GitHub App ID.
            github_app_key (str): GitHub App key.
            github_app_key_content (str): GitHub App key content.
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

            elif oauth_app_token:
                session_token = oauth_app_token

            elif github_app_id and (github_app_key or github_app_key_content):
                app_id = github_app_id
                if github_app_key:
                    with open(github_app_key, "r") as rsa_key:
                        app_key = rsa_key.read()
                else:
                    app_key = format_rsa_key(github_app_key_content)

            else:
                # PAT
                logger.info(
                    "Looking for GITHUB_PERSONAL_ACCESS_TOKEN environment variable as user has not provided any token...."
                )
                session_token = environ.get("GITHUB_PERSONAL_ACCESS_TOKEN", "")

                if not session_token:
                    # OAUTH
                    logger.info(
                        "Looking for GITHUB_OAUTH_APP_TOKEN environment variable as user has not provided any token...."
                    )
                    session_token = environ.get("GITHUB_OAUTH_APP_TOKEN", "")

                    if not session_token:
                        # APP
                        logger.info(
                            "Looking for GITHUB_APP_ID and GITHUB_APP_KEY environment variables as user has not provided any token...."
                        )
                        app_id = environ.get("GITHUB_APP_ID", "")
                        app_key = format_rsa_key(environ.get("GITHUB_APP_KEY", ""))

                        if app_id and app_key:
                            pass

            if not session_token and not (app_id and app_key):
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

    @staticmethod
    def setup_identity(
        session: GithubSession,
    ) -> Union[GithubIdentityInfo, GithubAppIdentityInfo]:
        """
        Returns the GitHub identity information

        Returns:
            GithubIdentityInfo | GithubAppIdentityInfo: An instance of GithubIdentityInfo or GithubAppIdentityInfo containing the identity information.
        """

        try:
            retry_config = GithubRetry(total=3)
            if session.token:
                auth = Auth.Token(session.token)
                g = Github(auth=auth, retry=retry_config)
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

            elif session.id != 0 and session.key:
                auth = Auth.AppAuth(session.id, session.key)
                gi = GithubIntegration(auth=auth, retry=retry_config)
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

    @staticmethod
    def validate_provider_id(
        session: GithubSession,
        provider_id: str,
    ) -> None:
        """
        Validate that the provider ID (username or organization) is accessible with the given credentials.

        Args:
            session (GithubSession): The GitHub session with authentication.
            provider_id (str): The provider ID to validate (username or organization name).

        Raises:
            GithubInvalidProviderIdError: If the provider ID is not accessible with the given credentials.

        Examples:
            >>> GithubProvider.validate_provider_id(session, "my-username")
            >>> GithubProvider.validate_provider_id(session, "my-organization")
        """
        try:
            retry_config = GithubRetry(total=3)

            if session.token:
                # For Personal Access Token and OAuth App Token
                auth = Auth.Token(session.token)
                g = Github(auth=auth, retry=retry_config)

                # First check if the provider ID is the authenticated user
                authenticated_user = g.get_user()
                if authenticated_user.login == provider_id:
                    return

                # Then check if the provider ID is an organization the token has access to
                try:
                    g.get_organization(provider_id)
                    return
                except Exception:
                    # Organization doesn't exist or the token doesn't have access to it
                    pass

                raise GithubInvalidProviderIdError(
                    file=os.path.basename(__file__),
                    message=f"The provider ID '{provider_id}' is not accessible with the provided credentials. "
                    f"Authenticated user: {authenticated_user.login}",
                )

            elif session.id != 0 and session.key:
                # For GitHub App
                auth = Auth.AppAuth(session.id, session.key)
                gi = GithubIntegration(auth=auth, retry=retry_config)

                # Check if the provider ID is in the app's installations
                for installation in gi.get_installations():
                    try:
                        # Check if the installation id is the username or organization id
                        account_login = installation.raw_data.get("account", {}).get(
                            "login"
                        )
                        if account_login == provider_id:
                            return
                    except Exception:
                        continue

                raise GithubInvalidProviderIdError(
                    file=os.path.basename(__file__),
                    message=f"The provider ID '{provider_id}' is not accessible with the provided GitHub App credentials.",
                )

        except GithubInvalidProviderIdError:
            # Re-raise the specific exception
            raise
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise GithubInvalidProviderIdError(
                file=os.path.basename(__file__),
                original_exception=error,
                message=f"Error validating provider ID '{provider_id}'",
            )

    @staticmethod
    def test_connection(
        personal_access_token: str = "",
        oauth_app_token: str = "",
        github_app_key: str = "",
        github_app_key_content: str = "",
        github_app_id: int = 0,
        raise_on_exception: bool = True,
        provider_id: str = None,
    ) -> Connection:
        """Test connection to GitHub.

        Test the connection to GitHub using the provided credentials.

        Args:
            personal_access_token (str): GitHub personal access token.
            oauth_app_token (str): GitHub OAuth App token.
            github_app_key (str): GitHub App key.
            github_app_key_content (str): GitHub App key content.
            github_app_id (int): GitHub App ID.
            raise_on_exception (bool): Flag indicating whether to raise an exception if the connection fails.
            provider_id (str): The provider ID, in this case it's the GitHub organization/username.

        Returns:
            Connection: Connection object with success status or error information.

        Raises:
            Exception: If failed to test the connection to GitHub.
            GithubEnvironmentVariableError: If environment variables are missing.
            GithubInvalidTokenError: If the provided token is invalid.
            GithubInvalidCredentialsError: If the provided App credentials are invalid.
            GithubSetUpSessionError: If there is an error setting up the session.
            GithubSetUpIdentityError: If there is an error setting up the identity.
            GithubInvalidProviderIdError: If the provided provider ID is not accessible with the given credentials.

        Examples:
            >>> GithubProvider.test_connection(personal_access_token="ghp_xxxxxxxxxxxxxxxx")
            Connection(is_connected=True)
            >>> GithubProvider.test_connection(github_app_id=12345, github_app_key="/path/to/key.pem")
            Connection(is_connected=True)
            >>> GithubProvider.test_connection(provider_id="my-org")
            Connection(is_connected=True)
        """
        try:
            # Set up the GitHub session
            session = GithubProvider.setup_session(
                personal_access_token=personal_access_token,
                oauth_app_token=oauth_app_token,
                github_app_id=github_app_id,
                github_app_key=github_app_key,
                github_app_key_content=github_app_key_content,
            )

            # Set up the identity to test the connection
            GithubProvider.setup_identity(session)

            # Validate provider ID if provided
            if provider_id:
                GithubProvider.validate_provider_id(session, provider_id)

            return Connection(is_connected=True)
        except GithubInvalidProviderIdError as provider_id_error:
            logger.critical(
                f"{provider_id_error.__class__.__name__}[{provider_id_error.__traceback__.tb_lineno}]: {provider_id_error}"
            )
            if raise_on_exception:
                raise provider_id_error
            return Connection(error=provider_id_error)
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise error
            return Connection(error=error)
