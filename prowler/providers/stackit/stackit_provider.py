import os
from typing import Optional
from uuid import UUID

from colorama import Style

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider
from prowler.providers.stackit.exceptions.exceptions import (
    StackITAPIError,
    StackITInvalidProjectIdError,
    StackITInvalidTokenError,
    StackITNonExistentTokenError,
    StackITSetUpIdentityError,
    StackITSetUpSessionError,
)
from prowler.providers.stackit.lib.mutelist.mutelist import StackITMutelist
from prowler.providers.stackit.models import StackITIdentityInfo


class StackitProvider(Provider):
    """
    StackIT Provider class to handle the StackIT provider

    Attributes:
    - _type: str -> The type of the provider, which is set to "stackit".
    - _api_token: str -> The API token for authentication with StackIT.
    - _project_id: str -> The StackIT project ID to audit.
    - _identity: StackITIdentityInfo -> The identity information for the StackIT provider.
    - _audit_config: dict -> The audit configuration for the StackIT provider.
    - _mutelist: StackITMutelist -> The mutelist object associated with the StackIT provider.
    - audit_metadata: Audit_Metadata -> The audit metadata for the StackIT provider.

    Methods:
    - __init__: Initializes the StackIT provider.
    - type: Returns the type of the StackIT provider.
    - identity: Returns the identity of the StackIT provider (ex: project_id).
    - session: Returns the session/configuration for API calls.
    - audit_config: Returns the audit configuration for the StackIT provider.
    - fixer_config: Returns the fixer configuration.
    - mutelist: Returns the mutelist object associated with the StackIT provider.
    - validate_arguments: Validates the StackIT provider arguments (ex: api_token, project_id).
    - print_credentials: Prints the StackIT credentials information (ex: project_id).
    - setup_session: Set up the StackIT session with the specified authentication method.
    - test_connection: Tests the provider connection.
    """

    _type: str = "stackit"
    _api_token: Optional[str]
    _project_id: Optional[str]
    _session: Optional[dict]
    _identity: StackITIdentityInfo
    _audit_config: dict
    _mutelist: StackITMutelist
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        api_token: str = None,
        project_id: str = None,
        config_path: str = None,
        fixer_config: dict = None,
        mutelist_path: str = None,
        mutelist_content: dict = None,
    ):
        """
        Initializes the StackIT provider.

        Args:
            - api_token: The StackIT API token for authentication
            - project_id: The StackIT project ID to audit
            - config_path: The path to the configuration file.
            - fixer_config: The fixer configuration.
            - mutelist_path: The path to the mutelist file.
            - mutelist_content: The mutelist content.
        """
        logger.info("Initializing StackIT Provider...")

        # 1) Store argument values
        self._api_token = api_token or os.getenv("STACKIT_API_TOKEN")
        self._project_id = project_id or os.getenv("STACKIT_PROJECT_ID")

        # 2) Validate credentials format (following Azure's validation pattern)
        try:
            self.validate_arguments(self._api_token, self._project_id)
        except StackITNonExistentTokenError:
            logger.critical(
                "StackIT API token is required. Provide it via --stackit-api-token or STACKIT_API_TOKEN environment variable."
            )
            raise
        except StackITInvalidProjectIdError:
            logger.critical(
                "StackIT project ID must be a valid UUID. Provide it via --stackit-project-id or STACKIT_PROJECT_ID environment variable."
            )
            raise

        # 3) Load audit_config, fixer_config, mutelist
        self._fixer_config = fixer_config if fixer_config else {}
        if not config_path:
            config_path = default_config_file_path
        self._audit_config = load_and_validate_config_file(self._type, config_path)

        if mutelist_content:
            self._mutelist = StackITMutelist(mutelist_content=mutelist_content)
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self._type)
            self._mutelist = StackITMutelist(mutelist_path=mutelist_path)

        # 4) Initialize session configuration
        self._session = None
        try:
            self.setup_session()
        except Exception as e:
            logger.critical(f"Error setting up StackIT session: {e}")
            raise StackITSetUpSessionError(
                original_exception=e,
                message=f"Failed to set up StackIT session: {str(e)}",
            )

        # 5) Create StackITIdentityInfo object and fetch project name
        try:
            project_name = self._get_project_name()
            self._identity = StackITIdentityInfo(
                project_id=self._project_id,
                project_name=project_name,
            )
        except StackITInvalidTokenError:
            # Re-raise authentication errors without wrapping to avoid verbose output
            raise
        except Exception as e:
            logger.critical(f"Error setting up StackIT identity: {e}")
            raise StackITSetUpIdentityError(
                original_exception=e,
                message=f"Failed to set up StackIT identity: {str(e)}",
            )

        # 6) Register as global provider
        Provider.set_global_provider(self)

    @property
    def type(self) -> str:
        """
        Returns the type of the provider ("stackit").
        """
        return self._type

    @property
    def identity(self) -> StackITIdentityInfo:
        """
        Returns the StackITIdentityInfo object, which contains project_id, etc.
        """
        return self._identity

    @property
    def session(self) -> dict:
        """
        Returns the session configuration for StackIT API calls.
        This includes the API token and project ID needed for SDK initialization.
        """
        return self._session

    @property
    def audit_config(self) -> dict:
        """
        Returns the audit configuration loaded from file or default settings.
        """
        return self._audit_config

    @property
    def fixer_config(self) -> dict:
        """
        Returns any fixer configuration provided to the StackIT provider.
        """
        return self._fixer_config

    @property
    def mutelist(self) -> StackITMutelist:
        """
        Returns the StackITMutelist object for handling any muted checks.
        """
        return self._mutelist

    @staticmethod
    def validate_arguments(api_token: str, project_id: str) -> None:
        """
        Validates StackIT static arguments format before use.

        This method follows the same pattern as Azure provider validation,
        validating format before attempting API calls for better error messages
        and faster failure on invalid input.

        Args:
            api_token: The StackIT API token
            project_id: The StackIT project ID (must be valid UUID format)

        Raises:
            StackITNonExistentTokenError: If api_token is missing or invalid
            StackITInvalidProjectIdError: If project_id is missing or not a valid UUID
        """
        # Validate API token is not empty
        if not api_token or not api_token.strip():
            raise StackITNonExistentTokenError(
                message="StackIT API token is required for authentication"
            )

        # Validate project_id is not empty
        if not project_id or not project_id.strip():
            raise StackITInvalidProjectIdError(
                message="StackIT project ID is required for auditing"
            )

        # Validate project_id is a valid UUID format
        # StackIT uses UUIDs for project IDs, similar to Azure subscription IDs
        try:
            UUID(project_id)
        except ValueError as e:
            raise StackITInvalidProjectIdError(
                original_exception=e,
                message=f"StackIT project ID must be a valid UUID format, got: {project_id}",
            )

    def print_credentials(self) -> None:
        """
        Prints the StackIT credentials in a simple box format.
        """
        # Build credential lines
        lines = []
        if self._identity.project_name:
            lines.append(f"  Project Name: {self._identity.project_name}")
        lines.append(f"  Project ID: {self._project_id}")
        lines.append("  API Token: ***REDACTED***")

        report_lines = ["\n".join(lines)]

        report_title = (
            f"{Style.BRIGHT}Using the StackIT credentials below:{Style.RESET_ALL}"
        )
        print_boxes(report_lines, report_title)

    def setup_session(self) -> None:
        """
        Set up the StackIT session configuration.

        This creates a session dictionary containing credentials
        that will be used by service clients.
        """
        try:
            # Store session configuration for use by service clients
            self._session = {
                "api_token": self._api_token,
                "project_id": self._project_id,
            }
            logger.info("StackIT session configuration set up successfully.")
        except Exception as e:
            logger.critical(f"Error in setup_session: {e}")
            raise e

    def _get_project_name(self) -> str:
        """
        Fetch the project name from the StackIT Resource Manager API.

        This also serves as a credential validation check - if the API token is
        invalid or expired, this will fail during provider initialization.

        Returns:
            str: The project name, or empty string if unavailable

        Raises:
            StackITInvalidTokenError: If the API token is invalid or expired
        """
        try:
            import contextlib
            import sys

            from stackit.core.configuration import Configuration
            from stackit.resourcemanager import DefaultApi

            # Suppress SDK stderr warnings during initialization
            @contextlib.contextmanager
            def suppress_stderr():
                original_stderr = sys.stderr
                try:
                    sys.stderr = open(os.devnull, 'w')
                    yield
                finally:
                    sys.stderr.close()
                    sys.stderr = original_stderr

            # Configure SDK with API token (thread-safe), suppressing warnings
            with suppress_stderr():
                config = Configuration(service_account_token=self._api_token)
                client = DefaultApi(config)

                # Fetch project details - this validates the token
                response = client.get_project(id=self._project_id)

            # Extract project name from response
            if hasattr(response, "name"):
                project_name = response.name
            elif isinstance(response, dict):
                project_name = response.get("name", "")
            else:
                project_name = ""

            logger.info(f"Successfully retrieved project name: {project_name}")
            return project_name

        except ImportError:
            logger.warning(
                "stackit-resourcemanager package not available. "
                "Project name will not be displayed in reports. "
                "Install with: pip install stackit-resourcemanager"
            )
            return ""
        except Exception as e:
            # Use centralized error handler for authentication errors
            try:
                StackitProvider.handle_api_error(e)
            except StackITInvalidTokenError:
                # Re-raise authentication errors to fail provider initialization
                raise
            # For other errors, log warning and continue
            logger.warning(
                f"Unable to fetch project name from StackIT API: {e}. "
                f"Project name will not be displayed in reports."
            )
            return ""

    @staticmethod
    def handle_api_error(exception: Exception) -> None:
        """
        Centralized handler for StackIT API errors across all services.

        Detects authentication errors (401) and raises StackITInvalidTokenError.
        This method should be called by all services when catching API exceptions.

        Args:
            exception: The exception caught from a StackIT API call

        Raises:
            StackITInvalidTokenError: If the error is a 401 Unauthorized
            Exception: Re-raises the original exception if not a 401
        """
        # Check if this is an authentication error (401 Unauthorized)
        if hasattr(exception, "status") and exception.status == 401:
            logger.critical(
                "StackIT API token is invalid or has expired. "
                "Generate a new token with: stackit auth activate-service-account "
                "--service-account-key-path <path> --only-print-access-token"
            )
            raise StackITInvalidTokenError(
                file="stackit_provider.py",
                original_exception=None,  # Don't include verbose HTTP details
                message="Invalid or expired API token",
            )
        # Re-raise other exceptions
        raise exception

    @staticmethod
    def test_connection(
        api_token: str,
        project_id: str,
        raise_on_exception: bool = True,
    ) -> Connection:
        """
        Test connection to StackIT by validating credentials.

        This method attempts to validate the API token and project ID
        by making a simple API call to StackIT services using the SDK.

        Args:
            api_token (str): StackIT API token
            project_id (str): StackIT project ID
            raise_on_exception (bool): If True, raise the caught exception;
                                       if False, return Connection(error=exception).

        Returns:
            Connection:
                Connection(is_connected=True) if success,
                otherwise Connection(error=Exception or custom error).
        """
        try:
            # 1) Validate arguments
            if not api_token or not project_id:
                error_msg = (
                    "StackIT test_connection error: missing api_token or project_id"
                )
                logger.error(error_msg)
                if raise_on_exception:
                    raise ValueError(error_msg)
                return Connection(error=ValueError(error_msg))

            # 2) Test connection by attempting to use the StackIT SDK
            try:
                from stackit.core.configuration import Configuration
                from stackit.objectstorage import DefaultApi

                # Pass the API token directly to Configuration (thread-safe approach)
                # This avoids manipulating global environment variables
                # Note: project_id is passed to API methods, not to Configuration
                config = Configuration(service_account_token=api_token)

                # Create DefaultApi client directly with Configuration
                # DefaultApi takes Configuration directly, not ApiClient
                client = DefaultApi(config)

                # Test with a simple API call (list buckets)
                # STACKIT has regions: eu01 (Germany South) and eu02 (Austria West)
                client.list_buckets(project_id=project_id, region="eu01")

                logger.info(
                    "StackIT test_connection: Successfully connected using StackIT SDK."
                )
                return Connection(is_connected=True)
            except ImportError as e:
                error_msg = f"StackIT SDK not available: {e}. Please ensure stackit-core and stackit-iaas are installed."
                logger.error(error_msg)
                if raise_on_exception:
                    raise ImportError(error_msg)
                return Connection(error=ImportError(error_msg))
            except Exception as test_error:
                error_msg = f"Failed to connect to StackIT using SDK: {str(test_error)}"
                logger.error(error_msg)
                if raise_on_exception:
                    raise StackITAPIError(
                        original_exception=test_error, message=error_msg
                    )
                return Connection(
                    error=StackITAPIError(
                        original_exception=test_error, message=error_msg
                    )
                )

        except Exception as e:
            logger.critical(f"{e.__class__.__name__}[{e.__traceback__.tb_lineno}]: {e}")
            if raise_on_exception:
                raise e
            return Connection(error=e)
