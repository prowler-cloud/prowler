import os
from os import environ

import requests
from colorama import Fore, Style

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.utils.utils import print_boxes
from prowler.providers.cloudflare.exceptions.exceptions import (
    CloudflareEnvironmentVariableError,
    CloudflareInvalidCredentialsError,
    CloudflareSetUpIdentityError,
    CloudflareSetUpSessionError,
)
from prowler.providers.cloudflare.lib.mutelist.mutelist import CloudflareMutelist
from prowler.providers.cloudflare.models import (
    CloudflareIdentityInfo,
    CloudflareSession,
)
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider


class CloudflareProvider(Provider):
    """
    Cloudflare Provider class

    This class is responsible for setting up the Cloudflare provider, including the session, identity,
    audit configuration, fixer configuration, and mutelist.

    Attributes:
        _type (str): The type of the provider.
        _auth_method (str): The authentication method used by the provider.
        _session (CloudflareSession): The session object for the provider.
        _identity (CloudflareIdentityInfo): The identity information for the provider.
        _audit_config (dict): The audit configuration for the provider.
        _fixer_config (dict): The fixer configuration for the provider.
        _mutelist (Mutelist): The mutelist for the provider.
        _account_ids (list): List of account IDs to scan.
        _zone_ids (list): List of zone IDs to scan.
        audit_metadata (Audit_Metadata): The audit metadata for the provider.
    """

    _type: str = "cloudflare"
    _auth_method: str = None
    _session: CloudflareSession
    _identity: CloudflareIdentityInfo
    _audit_config: dict
    _mutelist: Mutelist
    _account_ids: list
    _zone_ids: list
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        # Authentication credentials
        api_token: str = "",
        api_key: str = "",
        api_email: str = "",
        # Provider configuration
        config_path: str = None,
        config_content: dict = None,
        fixer_config: dict = {},
        mutelist_path: str = None,
        mutelist_content: dict = None,
        account_ids: list = None,
        zone_ids: list = None,
    ):
        """
        Cloudflare Provider constructor

        Args:
            api_token (str): Cloudflare API Token.
            api_key (str): Cloudflare API Key.
            api_email (str): Cloudflare API Email (used with API Key).
            config_path (str): Path to the audit configuration file.
            config_content (dict): Audit configuration content.
            fixer_config (dict): Fixer configuration content.
            mutelist_path (str): Path to the mutelist file.
            mutelist_content (dict): Mutelist content.
            account_ids (list): List of account IDs to scan.
            zone_ids (list): List of zone IDs to scan.
        """
        logger.info("Instantiating Cloudflare Provider...")

        # Set scoping parameters
        self._account_ids = account_ids or []
        self._zone_ids = zone_ids or []

        self._session = CloudflareProvider.setup_session(api_token, api_key, api_email)

        # Set the authentication method
        if api_token:
            self._auth_method = "API Token"
        elif api_key and api_email:
            self._auth_method = "API Key + Email"
        elif environ.get("CLOUDFLARE_API_TOKEN", ""):
            self._auth_method = "Environment Variable for API Token"
        elif environ.get("CLOUDFLARE_API_KEY", "") and environ.get(
            "CLOUDFLARE_API_EMAIL", ""
        ):
            self._auth_method = "Environment Variables for API Key and Email"

        self._identity = CloudflareProvider.setup_identity(self._session)

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
            self._mutelist = CloudflareMutelist(
                mutelist_content=mutelist_content,
            )
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = CloudflareMutelist(
                mutelist_path=mutelist_path,
            )
        Provider.set_global_provider(self)

    @property
    def auth_method(self):
        """Returns the authentication method for the Cloudflare provider."""
        return self._auth_method

    @property
    def session(self):
        """Returns the session object for the Cloudflare provider."""
        return self._session

    @property
    def identity(self):
        """Returns the identity information for the Cloudflare provider."""
        return self._identity

    @property
    def type(self):
        """Returns the type of the Cloudflare provider."""
        return self._type

    @property
    def audit_config(self):
        return self._audit_config

    @property
    def fixer_config(self):
        return self._fixer_config

    @property
    def mutelist(self) -> CloudflareMutelist:
        """
        mutelist method returns the provider's mutelist.
        """
        return self._mutelist

    @property
    def account_ids(self) -> list:
        """
        account_ids method returns the provider's account ID list for scoping.
        """
        return self._account_ids

    @property
    def zone_ids(self) -> list:
        """
        zone_ids method returns the provider's zone ID list for scoping.
        """
        return self._zone_ids

    @staticmethod
    def setup_session(
        api_token: str = None,
        api_key: str = None,
        api_email: str = None,
    ) -> CloudflareSession:
        """
        Returns the Cloudflare session with authentication credentials.

        Args:
            api_token (str): Cloudflare API Token.
            api_key (str): Cloudflare API Key.
            api_email (str): Cloudflare API Email.

        Returns:
            CloudflareSession: Authenticated session credentials for API requests.
        """

        session_api_token = ""
        session_api_key = ""
        session_api_email = ""

        try:
            # Ensure that at least one authentication method is selected
            if api_token:
                session_api_token = api_token
            elif api_key and api_email:
                session_api_key = api_key
                session_api_email = api_email
            else:
                # Try API Token from environment variable
                logger.info(
                    "Looking for CLOUDFLARE_API_TOKEN environment variable as user has not provided any credentials...."
                )
                session_api_token = environ.get("CLOUDFLARE_API_TOKEN", "")

                if not session_api_token:
                    # Try API Key + Email from environment variables
                    logger.info(
                        "Looking for CLOUDFLARE_API_KEY and CLOUDFLARE_API_EMAIL environment variables...."
                    )
                    session_api_key = environ.get("CLOUDFLARE_API_KEY", "")
                    session_api_email = environ.get("CLOUDFLARE_API_EMAIL", "")

            if not session_api_token and not (session_api_key and session_api_email):
                raise CloudflareEnvironmentVariableError(
                    file=os.path.basename(__file__),
                    message="No authentication method selected and no environment variables were found.",
                )

            credentials = CloudflareSession(
                api_token=session_api_token,
                api_key=session_api_key,
                api_email=session_api_email,
            )

            return credentials

        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise CloudflareSetUpSessionError(
                original_exception=error,
            )

    @staticmethod
    def setup_identity(session: CloudflareSession) -> CloudflareIdentityInfo:
        """
        Returns the Cloudflare identity information

        Returns:
            CloudflareIdentityInfo: An instance of CloudflareIdentityInfo containing the identity information.
        """

        try:
            # Setup headers for API requests
            headers = CloudflareProvider._get_headers(session)

            # Verify user endpoint to get account information
            response = requests.get(
                "https://api.cloudflare.com/client/v4/user", headers=headers, timeout=10
            )

            if response.status_code != 200:
                raise CloudflareInvalidCredentialsError(
                    message=f"Failed to authenticate with Cloudflare API: {response.status_code} - {response.text}"
                )

            try:
                user_data = response.json()
            except Exception as json_error:
                raise CloudflareInvalidCredentialsError(
                    message=f"Failed to parse Cloudflare API response: {json_error}. Response text: {response.text[:200]}"
                )

            if not user_data:
                raise CloudflareInvalidCredentialsError(
                    message=f"Cloudflare API returned empty response. Status: {response.status_code}"
                )

            if not user_data.get("success", False):
                error_messages = user_data.get("errors", [])
                raise CloudflareInvalidCredentialsError(
                    message=f"Cloudflare API authentication failed: {error_messages}"
                )

            result = user_data.get("result")
            if not result:
                raise CloudflareInvalidCredentialsError(
                    message=f"Cloudflare API returned empty result. Full response: {user_data}"
                )

            identity = CloudflareIdentityInfo(
                account_id=str(result.get("id", "")),
                account_name=result.get("username") or result.get("email", "Unknown"),
                account_email=result.get("email", ""),
            )

            return identity

        except CloudflareInvalidCredentialsError:
            raise
        except Exception as error:
            # Get line number safely
            lineno = error.__traceback__.tb_lineno if error.__traceback__ else "unknown"
            logger.critical(f"{error.__class__.__name__}[{lineno}]: {error}")
            raise CloudflareSetUpIdentityError(
                original_exception=error,
            )

    @staticmethod
    def _get_headers(session: CloudflareSession) -> dict:
        """
        Returns HTTP headers for Cloudflare API requests.

        Args:
            session (CloudflareSession): The Cloudflare session with authentication.

        Returns:
            dict: Headers dictionary with authentication credentials.
        """
        headers = {"Content-Type": "application/json"}

        if session.api_token:
            headers["Authorization"] = f"Bearer {session.api_token}"
        elif session.api_key and session.api_email:
            headers["X-Auth-Key"] = session.api_key
            headers["X-Auth-Email"] = session.api_email

        return headers

    def print_credentials(self):
        """
        Prints the Cloudflare credentials.

        Usage:
            >>> self.print_credentials()
        """
        report_lines = [
            f"Cloudflare Account ID: {Fore.YELLOW}{self.identity.account_id}{Style.RESET_ALL}",
            f"Cloudflare Account Name: {Fore.YELLOW}{self.identity.account_name}{Style.RESET_ALL}",
            f"Cloudflare Account Email: {Fore.YELLOW}{self.identity.account_email}{Style.RESET_ALL}",
            f"Authentication Method: {Fore.YELLOW}{self.auth_method}{Style.RESET_ALL}",
        ]
        report_title = (
            f"{Style.BRIGHT}Using the Cloudflare credentials below:{Style.RESET_ALL}"
        )
        print_boxes(report_lines, report_title)

    @staticmethod
    def test_connection(
        api_token: str = "",
        api_key: str = "",
        api_email: str = "",
        raise_on_exception: bool = True,
    ) -> Connection:
        """Test connection to Cloudflare.

        Test the connection to Cloudflare using the provided credentials.

        Args:
            api_token (str): Cloudflare API Token.
            api_key (str): Cloudflare API Key.
            api_email (str): Cloudflare API Email.
            raise_on_exception (bool): Flag indicating whether to raise an exception if the connection fails.

        Returns:
            Connection: Connection object with success status or error information.

        Raises:
            Exception: If failed to test the connection to Cloudflare.
            CloudflareEnvironmentVariableError: If environment variables are missing.
            CloudflareInvalidCredentialsError: If the provided credentials are invalid.
            CloudflareSetUpSessionError: If there is an error setting up the session.
            CloudflareSetUpIdentityError: If there is an error setting up the identity.

        Examples:
            >>> CloudflareProvider.test_connection(api_token="your-api-token")
            Connection(is_connected=True)
            >>> CloudflareProvider.test_connection(api_key="your-api-key", api_email="your@email.com")
            Connection(is_connected=True)
        """
        try:
            # Set up the Cloudflare session
            session = CloudflareProvider.setup_session(
                api_token=api_token,
                api_key=api_key,
                api_email=api_email,
            )

            # Set up the identity to test the connection
            CloudflareProvider.setup_identity(session)

            return Connection(is_connected=True)
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise error
            return Connection(error=error)
