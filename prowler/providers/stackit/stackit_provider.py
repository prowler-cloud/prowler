import contextlib
import io
import os
import pathlib
from typing import Optional
from uuid import UUID

from colorama import Style

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.utils.utils import open_file, parse_json_file, print_boxes
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

STACKIT_REGIONS_JSON_FILE = "stackit_regions_by_service.json"


@contextlib.contextmanager
def suppress_stderr():
    with contextlib.redirect_stderr(io.StringIO()):
        yield


class StackitProvider(Provider):
    """
    StackIT Provider class to handle the StackIT provider

    Attributes:
    - _type: str -> The type of the provider, which is set to "stackit".
    - _project_id: str -> The StackIT project ID to audit.
    - _service_account_key_path: str -> Path to a StackIT service account key
      JSON file. The SDK mints and refreshes access tokens internally.
    - _service_account_key: str -> Inline JSON content of a StackIT service
      account key, for secret-manager driven deployments that do not write
      the key to disk. Takes precedence over the key path when both are set.
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
    - validate_arguments: Validates the StackIT provider arguments (key path, project_id).
    - print_credentials: Prints the StackIT credentials information (ex: project_id).
    - setup_session: Set up the StackIT session with the specified authentication method.
    - test_connection: Tests the provider connection.
    """

    _type: str = "stackit"
    _project_id: Optional[str]
    _service_account_key_path: Optional[str]
    _service_account_key: Optional[str]
    _session: Optional[dict]
    _identity: StackITIdentityInfo
    _audit_config: dict
    _mutelist: StackITMutelist
    _scan_unused_services: bool = False
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        project_id: str = None,
        service_account_key_path: str = None,
        service_account_key: str = None,
        regions: set = None,
        scan_unused_services: bool = False,
        config_path: str = None,
        fixer_config: dict = None,
        mutelist_path: str = None,
        mutelist_content: dict = None,
    ):
        """
        Initializes the StackIT provider.

        Args:
            - project_id: The StackIT project ID to audit.
            - service_account_key_path: Path to a StackIT service account key
              JSON file. The SDK mints and refreshes access tokens internally
              from this key. Read from ``STACKIT_SERVICE_ACCOUNT_KEY_PATH``
              when not provided.
            - service_account_key: Inline JSON content of a StackIT service
              account key, intended for CI/CD where the secret is fetched
              from a secret manager and not persisted to disk. Read from
              ``STACKIT_SERVICE_ACCOUNT_KEY`` when not provided. Takes
              precedence over ``service_account_key_path`` when both are set.
            - regions: The list of regions to audit.
            - config_path: The path to the configuration file.
            - fixer_config: The fixer configuration.
            - mutelist_path: The path to the mutelist file.
            - mutelist_content: The mutelist content.
        """
        logger.info("Initializing StackIT Provider...")

        # 1) Store argument values
        self._project_id = project_id or os.getenv("STACKIT_PROJECT_ID")
        self._service_account_key_path = service_account_key_path or os.getenv(
            "STACKIT_SERVICE_ACCOUNT_KEY_PATH"
        )
        self._service_account_key = service_account_key or os.getenv(
            "STACKIT_SERVICE_ACCOUNT_KEY"
        )
        self._audited_regions = regions if regions else self.get_regions()
        self._scan_unused_services = scan_unused_services

        # 2) Validate credentials format (following Azure's validation pattern)
        try:
            self.validate_arguments(
                self._project_id,
                self._service_account_key_path,
                self._service_account_key,
            )
        except StackITNonExistentTokenError:
            logger.critical(
                "StackIT service account credentials are required. Provide the "
                "key file path via --stackit-service-account-key-path / "
                "STACKIT_SERVICE_ACCOUNT_KEY_PATH, or the key content via "
                "--stackit-service-account-key / STACKIT_SERVICE_ACCOUNT_KEY."
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
                audited_regions=self._audited_regions,
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

    @staticmethod
    def read_stackit_regions_file() -> dict:
        """Read the STACKIT regions JSON file."""
        actual_directory = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        with open_file(f"{actual_directory}/{STACKIT_REGIONS_JSON_FILE}") as f:
            return parse_json_file(f)

    @staticmethod
    def get_regions() -> set:
        """Get all available STACKIT regions from the JSON file."""
        regions = set()
        data = StackitProvider.read_stackit_regions_file()
        for service in data["services"].values():
            regions.update(service["regions"])
        return regions

    @staticmethod
    def get_available_service_regions(service: str, audited_regions: set = None) -> set:
        """Get available regions for a specific service, filtered by audited_regions."""
        data = StackitProvider.read_stackit_regions_file()
        json_regions = set(data["services"].get(service, {}).get("regions", []))
        if audited_regions:
            return json_regions.intersection(audited_regions)
        return json_regions

    def generate_regional_clients(self, service: str = "iaas") -> dict:
        """Generate regional API clients for the given service.

        Returns dict: {"eu01": DefaultApi_client, "eu02": DefaultApi_client}
        """
        from stackit.iaas import DefaultApi

        regional_clients = {}
        service_regions = self.get_available_service_regions(
            service, self._audited_regions
        )

        for region in service_regions:
            with suppress_stderr():
                config = self._build_sdk_configuration(
                    self._service_account_key_path,
                    self._service_account_key,
                )
                client = DefaultApi(config)
                client.region = region  # Attach region attribute
                regional_clients[region] = client

        return regional_clients

    @staticmethod
    def _build_sdk_configuration(
        service_account_key_path: str, service_account_key: str = None
    ):
        """Build a ``stackit.core.configuration.Configuration`` from the
        configured service account credentials.

        Prefer the inlined key content over the path so secret-manager
        deployments (where the path may also be set as a default) work
        without writing the secret to disk. In both cases the SDK signs
        the RSA challenge and refreshes access tokens internally for the
        life of the scan.

        Kept as a static helper so ``test_connection`` (which has no provider
        instance) can reuse it.
        """
        from stackit.core.configuration import Configuration

        if service_account_key:
            return Configuration(service_account_key=service_account_key)
        return Configuration(service_account_key_path=service_account_key_path)

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
    def scan_unused_services(self) -> bool:
        return self._scan_unused_services

    @property
    def mutelist(self) -> StackITMutelist:
        """
        Returns the StackITMutelist object for handling any muted checks.
        """
        return self._mutelist

    @staticmethod
    def validate_arguments(
        project_id: str,
        service_account_key_path: str,
        service_account_key: str = None,
    ) -> None:
        """
        Validates StackIT static arguments format before use.

        Either the service account key file path or the inline key content
        must be supplied, and the project ID is always required and must be
        a valid UUID. This mirrors Azure's pattern of failing fast on input
        format issues before making any API calls.

        Args:
            project_id: The StackIT project ID (must be valid UUID format)
            service_account_key_path: Path to a service account key JSON file
                (optional when ``service_account_key`` is provided)
            service_account_key: Inline JSON content of a service account key
                (optional when ``service_account_key_path`` is provided)

        Raises:
            StackITNonExistentTokenError: If both ``service_account_key_path``
                and ``service_account_key`` are missing or empty
            StackITInvalidProjectIdError: If ``project_id`` is missing or not a
                valid UUID
        """
        has_path = bool(service_account_key_path and service_account_key_path.strip())
        has_key = bool(service_account_key and service_account_key.strip())
        if not has_path and not has_key:
            raise StackITNonExistentTokenError(
                message=(
                    "StackIT service account credentials are required: provide "
                    "the key file path (--stackit-service-account-key-path or "
                    "STACKIT_SERVICE_ACCOUNT_KEY_PATH) or the inline key content "
                    "(--stackit-service-account-key or STACKIT_SERVICE_ACCOUNT_KEY)"
                )
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

    @property
    def auth_method(self) -> str:
        """Auth method label used for findings and credentials box.

        StackIT authenticates with a service account key; the SDK signs
        the RSA challenge and refreshes access tokens internally.
        """
        return "service_account_key"

    def print_credentials(self) -> None:
        """
        Prints the StackIT credentials in a simple box format.
        """
        # Build credential lines
        lines = []
        if self._identity.project_name:
            lines.append(f"  Project Name: {self._identity.project_name}")
        lines.append(f"  Project ID: {self._project_id}")
        if self._service_account_key:
            lines.append("  Service Account Key: ***REDACTED*** (inline)")
        else:
            lines.append(f"  Service Account Key: {self._service_account_key_path}")
        lines.append("  Auth Method: service account key (auto-refresh)")

        report_lines = ["\n".join(lines)]

        report_title = (
            f"{Style.BRIGHT}Using the StackIT credentials below:{Style.RESET_ALL}"
        )
        print_boxes(report_lines, report_title)

    def setup_session(self) -> None:
        """
        Set up the StackIT session configuration.

        This creates a session dictionary containing the credentials
        used by service clients to build SDK ``Configuration`` objects.
        """
        try:
            self._session = {
                "project_id": self._project_id,
                "service_account_key_path": self._service_account_key_path,
                "service_account_key": self._service_account_key,
            }
            logger.info("StackIT session configuration set up successfully.")
        except Exception as e:
            logger.critical(f"Error in setup_session: {e}")
            raise e

    def _get_project_name(self) -> str:
        """
        Fetch the project name from the StackIT Resource Manager API.

        The project name is cosmetic (shown in the credentials box and in
        the ``account_name`` field of findings); a missing or unauthorized
        Resource Manager endpoint must not abort an otherwise valid IaaS
        scan. A service account can legitimately hold IaaS roles on a
        project without holding Resource Manager roles on it.

        Failure semantics:
            - HTTP 401 -> hard failure via :class:`StackITInvalidTokenError`
              (the credentials cannot mint a usable token).
            - HTTP 403 (or any other non-401 error) -> warning, returns
              an empty project name; the scan continues and per-service
              ``handle_api_error`` will abort later if the IaaS endpoints
              are also forbidden.

        Returns:
            str: The project name, or empty string if unavailable.

        Raises:
            StackITInvalidTokenError: If the credentials are rejected with a
                401 response when contacting Resource Manager.
        """
        try:
            from stackit.resourcemanager import DefaultApi

            with suppress_stderr():
                config = self._build_sdk_configuration(
                    self._service_account_key_path,
                    self._service_account_key,
                )
                client = DefaultApi(config)

                # Fetch project details - validates that the credentials
                # can mint a token; permission to read this specific
                # project is checked but optional.
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
            status = getattr(e, "status", None)
            if status == 401:
                # Bad credentials are a hard failure even at the cosmetic
                # Resource Manager lookup; keep the same behaviour as
                # ``handle_api_error`` so the user sees the same message.
                logger.critical(
                    "StackIT service account key was rejected by Resource "
                    "Manager (401). Verify the key file is current and has "
                    "not been revoked in the StackIT portal."
                )
                raise StackITInvalidTokenError(
                    file="stackit_provider.py",
                    original_exception=None,
                    message="StackIT service account key was rejected (401)",
                )
            if status == 403:
                logger.warning(
                    f"StackIT service account lacks the Resource Manager "
                    f"role on project {self._project_id} (403). The project "
                    f"name will not be displayed in reports, but IaaS "
                    f"checks will still run if the service account has the "
                    f"relevant IaaS role."
                )
                return ""
            logger.warning(
                f"Unable to fetch project name from StackIT API: {e}. "
                f"Project name will not be displayed in reports."
            )
            return ""

    @staticmethod
    def handle_api_error(exception: Exception) -> None:
        """
        Centralized handler for StackIT API errors across all services.

        Detects credential and permission errors (HTTP 401 and 403) and raises
        ``StackITInvalidTokenError`` so the scan aborts instead of continuing
        with partial data. All other exceptions are re-raised unchanged so
        callers can decide how to handle them (e.g. per-resource ``continue``).

        Args:
            exception: The exception caught from a StackIT API call

        Raises:
            StackITInvalidTokenError: If the error is a 401 Unauthorized or
                a 403 Forbidden response
            Exception: Re-raises the original exception otherwise
        """
        status = getattr(exception, "status", None)
        if status == 401:
            logger.critical(
                "StackIT service account key was rejected. Verify the key "
                "file referenced by STACKIT_SERVICE_ACCOUNT_KEY_PATH is the "
                "current one and has not been revoked in the StackIT portal."
            )
            raise StackITInvalidTokenError(
                file="stackit_provider.py",
                original_exception=None,  # Don't include verbose HTTP details
                message="StackIT service account key was rejected (401)",
            )
        if status == 403:
            logger.critical(
                "StackIT service account lacks the required permissions on this project. "
                "Ensure the service account has the necessary IAM roles."
            )
            raise StackITInvalidTokenError(
                file="stackit_provider.py",
                original_exception=None,  # Don't include verbose HTTP details
                message="Service account lacks required permissions on this project",
            )
        # Re-raise other exceptions unchanged
        raise exception

    @staticmethod
    def test_connection(
        project_id: str = None,
        service_account_key_path: str = None,
        service_account_key: str = None,
        raise_on_exception: bool = True,
    ) -> Connection:
        """
        Test connection to StackIT by validating credentials.

        This method validates the service account credentials and project ID
        by making a Resource Manager ``get_project`` call. Pass either the
        key file path or the inline key content; the SDK signs the RSA
        challenge and mints a short-lived access token internally.

        Args:
            project_id (str): StackIT project ID
            service_account_key_path (str): Path to a StackIT service account
                key JSON file (optional when ``service_account_key`` is given)
            service_account_key (str): Inline JSON content of a StackIT
                service account key (optional when
                ``service_account_key_path`` is given)
            raise_on_exception (bool): If True, raise the caught exception;
                                       if False, return Connection(error=exception).

        Returns:
            Connection:
                Connection(is_connected=True) if success,
                otherwise Connection(error=Exception or custom error).
        """
        try:
            # 1) Validate arguments using the same static checks as provider init.
            try:
                StackitProvider.validate_arguments(
                    project_id, service_account_key_path, service_account_key
                )
            except Exception as validation_error:
                logger.error(f"StackIT test_connection error: {validation_error}")
                if raise_on_exception:
                    raise validation_error
                return Connection(error=validation_error)

            # 2) Test connection with the same Resource Manager lookup used
            # during provider identity initialization.
            try:
                from stackit.resourcemanager import DefaultApi

                with suppress_stderr():
                    config = StackitProvider._build_sdk_configuration(
                        service_account_key_path,
                        service_account_key,
                    )
                    client = DefaultApi(config)
                    client.get_project(id=project_id)

                logger.info(
                    "StackIT test_connection: Successfully connected using StackIT Resource Manager."
                )
                return Connection(is_connected=True)
            except ImportError as e:
                error_msg = f"StackIT SDK not available: {e}. Please ensure stackit-core and stackit-resourcemanager are installed."
                logger.error(error_msg)
                if raise_on_exception:
                    raise ImportError(error_msg)
                return Connection(error=ImportError(error_msg))
            except Exception as test_error:
                try:
                    StackitProvider.handle_api_error(test_error)
                    if raise_on_exception:
                        raise test_error
                    return Connection(error=test_error)
                except StackITInvalidTokenError as auth_error:
                    if raise_on_exception:
                        raise auth_error
                    return Connection(error=auth_error)
                except Exception as api_error:
                    error_msg = (
                        "Failed to connect to StackIT using Resource Manager: "
                        f"{str(api_error)}"
                    )
                    logger.error(error_msg)
                    connection_error = StackITAPIError(
                        original_exception=api_error, message=error_msg
                    )
                    if raise_on_exception:
                        raise connection_error
                    return Connection(error=connection_error)

        except Exception as e:
            logger.critical(f"{e.__class__.__name__}[{e.__traceback__.tb_lineno}]: {e}")
            if raise_on_exception:
                raise e
            return Connection(error=e)
