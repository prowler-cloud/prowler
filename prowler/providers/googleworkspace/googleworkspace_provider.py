import json
import os
from os import environ

from colorama import Fore, Style
from google.oauth2 import service_account
from googleapiclient.discovery import build

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider
from prowler.providers.googleworkspace.exceptions.exceptions import (
    GoogleWorkspaceImpersonationError,
    GoogleWorkspaceInvalidCredentialsError,
    GoogleWorkspaceMissingDelegatedUserError,
    GoogleWorkspaceNoCredentialsError,
    GoogleWorkspaceSetUpIdentityError,
    GoogleWorkspaceSetUpSessionError,
)
from prowler.providers.googleworkspace.lib.mutelist.mutelist import (
    GoogleWorkspaceMutelist,
)
from prowler.providers.googleworkspace.models import (
    GoogleWorkspaceIdentityInfo,
    GoogleWorkspaceSession,
)


class GoogleworkspaceProvider(Provider):
    """
    Google Workspace Provider class

    This class is responsible for setting up the Google Workspace provider, including the session,
    identity, audit configuration, fixer configuration, and mutelist.

    Attributes:
        _type (str): The type of the provider.
        _session (GoogleWorkspaceSession): The session object for the provider.
        _identity (GoogleWorkspaceIdentityInfo): The identity information for the provider.
        _audit_config (dict): The audit configuration for the provider.
        _fixer_config (dict): The fixer configuration for the provider.
        _mutelist (GoogleWorkspaceMutelist): The mutelist for the provider.
        audit_metadata (Audit_Metadata): The audit metadata for the provider.
    """

    _type: str = "googleworkspace"
    _session: GoogleWorkspaceSession
    _identity: GoogleWorkspaceIdentityInfo
    _audit_config: dict
    _mutelist: GoogleWorkspaceMutelist
    audit_metadata: Audit_Metadata

    # Google Workspace Admin SDK OAuth2 scopes
    DIRECTORY_SCOPES = [
        "https://www.googleapis.com/auth/admin.directory.user.readonly",
        "https://www.googleapis.com/auth/admin.directory.domain.readonly",
        "https://www.googleapis.com/auth/admin.directory.customer.readonly",
    ]

    def __init__(
        self,
        # Authentication credentials
        credentials_file: str = None,
        credentials_content: str = None,
        delegated_user: str = None,
        # Provider configuration
        config_path: str = None,
        config_content: dict = None,
        fixer_config: dict = None,
        mutelist_path: str = None,
        mutelist_content: dict = None,
    ):
        """
        Google Workspace Provider constructor

        Args:
            credentials_file (str): Path to Service Account JSON credentials file.
            credentials_content (str): Service Account JSON credentials as a string.
            delegated_user (str): Email of the user to impersonate via Domain-Wide Delegation.
            config_path (str): Path to the audit configuration file.
            config_content (dict): Audit configuration content.
            fixer_config (dict): Fixer configuration content.
            mutelist_path (str): Path to the mutelist file.
            mutelist_content (dict): Mutelist content.
        """
        logger.info("Instantiating Google Workspace Provider...")

        # Mute Google API library logs to reduce noise
        import logging

        logging.getLogger("googleapiclient.discovery").setLevel(logging.ERROR)
        logging.getLogger("googleapiclient.discovery_cache").setLevel(logging.ERROR)

        self._session = GoogleworkspaceProvider.setup_session(
            credentials_file,
            credentials_content,
            delegated_user,
        )

        self._identity = GoogleworkspaceProvider.setup_identity(
            self._session,
            delegated_user,
        )

        # Audit Config
        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

        # Fixer Config
        self._fixer_config = fixer_config or {}

        # Mutelist
        if mutelist_content:
            self._mutelist = GoogleWorkspaceMutelist(
                mutelist_content=mutelist_content,
            )
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = GoogleWorkspaceMutelist(
                mutelist_path=mutelist_path,
            )

        Provider.set_global_provider(self)

    @property
    def session(self):
        """Returns the session object for the Google Workspace provider."""
        return self._session

    @property
    def identity(self):
        """Returns the identity information for the Google Workspace provider."""
        return self._identity

    @property
    def type(self):
        """Returns the type of the Google Workspace provider."""
        return self._type

    @property
    def audit_config(self):
        return self._audit_config

    @property
    def fixer_config(self):
        return self._fixer_config

    @property
    def mutelist(self) -> GoogleWorkspaceMutelist:
        """
        mutelist method returns the provider's mutelist.
        """
        return self._mutelist

    @staticmethod
    def setup_session(
        credentials_file: str = None,
        credentials_content: str = None,
        delegated_user: str = None,
    ) -> GoogleWorkspaceSession:
        """
        Sets up the Google Workspace session with Service Account and Domain-Wide Delegation.

        Args:
            credentials_file (str): Path to Service Account JSON credentials file.
            credentials_content (str): Service Account JSON credentials as a string.
            delegated_user (str): Email of the user to impersonate via Domain-Wide Delegation.

        Returns:
            GoogleWorkspaceSession: Authenticated session with delegated credentials.

        Raises:
            GoogleWorkspaceNoCredentialsError: If no credentials are provided.
            GoogleWorkspaceMissingDelegatedUserError: If delegated_user is not provided.
            GoogleWorkspaceInvalidCredentialsError: If credentials are invalid.
            GoogleWorkspaceImpersonationError: If impersonation fails.
            GoogleWorkspaceSetUpSessionError: If session setup fails.
        """
        try:
            # Check if delegated_user is provided (required for Domain-Wide Delegation)
            if not delegated_user:
                # Try environment variable
                delegated_user = environ.get("GOOGLEWORKSPACE_DELEGATED_USER", "")
                if not delegated_user:
                    raise GoogleWorkspaceMissingDelegatedUserError(
                        file=os.path.basename(__file__),
                        message="Delegated user email is required for Domain-Wide Delegation authentication",
                    )

            # Determine credentials source
            if credentials_file:
                logger.info(
                    f"Using Service Account credentials from file: {credentials_file}"
                )
                credentials = service_account.Credentials.from_service_account_file(
                    credentials_file,
                    scopes=GoogleworkspaceProvider.DIRECTORY_SCOPES,
                )
            elif credentials_content:
                logger.info("Using Service Account credentials from content")
                try:
                    credentials_data = json.loads(credentials_content)
                except json.JSONDecodeError as error:
                    raise GoogleWorkspaceInvalidCredentialsError(
                        file=os.path.basename(__file__),
                        original_exception=error,
                        message="Invalid JSON in credentials content",
                    )
                credentials = service_account.Credentials.from_service_account_info(
                    credentials_data,
                    scopes=GoogleworkspaceProvider.DIRECTORY_SCOPES,
                )
            else:
                # Try environment variables
                logger.info(
                    "Looking for GOOGLEWORKSPACE_CREDENTIALS_FILE or GOOGLEWORKSPACE_CREDENTIALS_CONTENT environment variables..."
                )
                env_file = environ.get("GOOGLEWORKSPACE_CREDENTIALS_FILE", "")
                env_content = environ.get("GOOGLEWORKSPACE_CREDENTIALS_CONTENT", "")

                if env_file:
                    logger.info(
                        f"Using Service Account credentials from environment variable file: {env_file}"
                    )
                    credentials = service_account.Credentials.from_service_account_file(
                        env_file,
                        scopes=GoogleworkspaceProvider.DIRECTORY_SCOPES,
                    )
                elif env_content:
                    logger.info(
                        "Using Service Account credentials from environment variable content"
                    )
                    try:
                        credentials_data = json.loads(env_content)
                    except json.JSONDecodeError as error:
                        raise GoogleWorkspaceInvalidCredentialsError(
                            file=os.path.basename(__file__),
                            original_exception=error,
                            message="Invalid JSON in GOOGLEWORKSPACE_CREDENTIALS_CONTENT",
                        )
                    credentials = service_account.Credentials.from_service_account_info(
                        credentials_data,
                        scopes=GoogleworkspaceProvider.DIRECTORY_SCOPES,
                    )
                else:
                    raise GoogleWorkspaceNoCredentialsError(
                        file=os.path.basename(__file__),
                        message="No credentials provided. Set the GOOGLEWORKSPACE_CREDENTIALS_FILE or GOOGLEWORKSPACE_CREDENTIALS_CONTENT environment variable.",
                    )

            # Perform Domain-Wide Delegation impersonation
            logger.info(f"Impersonating user: {delegated_user}")
            try:
                delegated_credentials = credentials.with_subject(delegated_user)
            except Exception as error:
                raise GoogleWorkspaceImpersonationError(
                    file=os.path.basename(__file__),
                    original_exception=error,
                    message=f"Failed to impersonate user '{delegated_user}'. Ensure Domain-Wide Delegation is configured.",
                )

            session = GoogleWorkspaceSession(credentials=delegated_credentials)
            return session

        except (
            GoogleWorkspaceNoCredentialsError,
            GoogleWorkspaceMissingDelegatedUserError,
            GoogleWorkspaceInvalidCredentialsError,
            GoogleWorkspaceImpersonationError,
        ):
            # Re-raise specific exceptions
            raise
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise GoogleWorkspaceSetUpSessionError(
                original_exception=error,
            )

    @staticmethod
    def setup_identity(
        session: GoogleWorkspaceSession,
        delegated_user: str,
    ) -> GoogleWorkspaceIdentityInfo:
        """
        Retrieves Google Workspace identity information using the Admin SDK.

        Args:
            session (GoogleWorkspaceSession): The authenticated session.
            delegated_user (str): The delegated user email.

        Returns:
            GoogleWorkspaceIdentityInfo: Identity information including domain and customer ID.

        Raises:
            GoogleWorkspaceSetUpIdentityError: If identity setup fails.
        """
        try:
            # Resolve delegated_user from environment if not provided
            if not delegated_user:
                delegated_user = environ.get("GOOGLEWORKSPACE_DELEGATED_USER", "")
                if not delegated_user:
                    raise GoogleWorkspaceMissingDelegatedUserError(
                        file=os.path.basename(__file__),
                        message="Delegated user email is required for identity setup",
                    )

            # Build the Admin SDK Directory service
            service = build(
                "admin",
                "directory_v1",
                credentials=session.credentials,
                cache_discovery=False,
            )

            # Get customer information (domain and customer ID)
            # First, extract domain from delegated user email
            domain = (
                delegated_user.split("@")[-1] if "@" in delegated_user else "unknown"
            )

            # Fetch customer ID using the Directory API
            # We'll use the special 'my_customer' alias to get the current customer
            try:
                customer_info = (
                    service.customers().get(customerKey="my_customer").execute()
                )
                customer_id = customer_info.get("id", "unknown")
            except Exception as error:
                logger.warning(
                    f"Could not fetch customer info, using 'my_customer': {error}"
                )
                customer_id = "my_customer"

            identity = GoogleWorkspaceIdentityInfo(
                domain=domain,
                customer_id=customer_id,
                delegated_user=delegated_user,
                profile="default",
            )

            logger.info(f"Google Workspace identity set up for domain: {domain}")
            return identity

        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise GoogleWorkspaceSetUpIdentityError(
                original_exception=error,
            )

    def print_credentials(self):
        """
        Prints the Google Workspace credentials.

        Usage:
            >>> self.print_credentials()
        """
        report_lines = [
            f"Google Workspace Domain: {Fore.YELLOW}{self.identity.domain}{Style.RESET_ALL}",
            f"Customer ID: {Fore.YELLOW}{self.identity.customer_id}{Style.RESET_ALL}",
            f"Delegated User: {Fore.YELLOW}{self.identity.delegated_user}{Style.RESET_ALL}",
            f"Authentication Method: {Fore.YELLOW}Service Account with Domain-Wide Delegation{Style.RESET_ALL}",
        ]
        report_title = f"{Style.BRIGHT}Using the Google Workspace credentials below:{Style.RESET_ALL}"
        print_boxes(report_lines, report_title)

    @staticmethod
    def test_connection(
        credentials_file: str = None,
        credentials_content: str = None,
        delegated_user: str = None,
        raise_on_exception: bool = True,
    ) -> Connection:
        """Test connection to Google Workspace.

        Test the connection to Google Workspace using the provided credentials.

        Args:
            credentials_file (str): Path to Service Account JSON credentials file.
            credentials_content (str): Service Account JSON credentials as a string.
            delegated_user (str): Email of the user to impersonate via Domain-Wide Delegation.
            raise_on_exception (bool): Flag indicating whether to raise an exception if the connection fails.

        Returns:
            Connection: Connection object with success status or error information.

        Raises:
            GoogleWorkspaceNoCredentialsError: If no credentials are provided.
            GoogleWorkspaceMissingDelegatedUserError: If delegated_user is not provided.
            GoogleWorkspaceSetUpSessionError: If there is an error setting up the session.
            GoogleWorkspaceSetUpIdentityError: If there is an error setting up the identity.

        Examples:
            >>> GoogleworkspaceProvider.test_connection(
            ...     credentials_file="sa.json",
            ...     delegated_user="prowler-reader@company.com"
            ... )
            Connection(is_connected=True)
        """
        try:
            # Set up the Google Workspace session
            session = GoogleworkspaceProvider.setup_session(
                credentials_file=credentials_file,
                credentials_content=credentials_content,
                delegated_user=delegated_user,
            )

            # Set up the identity to test the connection
            GoogleworkspaceProvider.setup_identity(session, delegated_user)

            return Connection(is_connected=True)
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise error
            return Connection(error=error)
