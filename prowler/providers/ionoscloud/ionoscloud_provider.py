import os
import pathlib

from colorama import Fore, Style

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider
from prowler.providers.ionoscloud.exceptions.exceptions import (
    IonosCloudInvalidCredentialsError,
    IonosCloudNoCredentialsError,
    IonosCloudSetUpSessionError,
)
from prowler.providers.ionoscloud.lib.mutelist.mutelist import IonosCloudMutelist
from prowler.providers.ionoscloud.models import (
    IonosCloudCredentials,
    IonosCloudIdentityInfo,
)


class IonoscloudProvider(Provider):
    """
    IonoscloudProvider is the main class for the IONOS Cloud provider.

    It handles authentication (username/password or token), identity resolution,
    audit configuration, and mutelist setup.

    Attributes:
        _type (str): Provider identifier used throughout Prowler.
        _session: Configured ionoscloud.ApiClient instance.
        _identity (IonosCloudIdentityInfo): Authenticated user information.
        _audit_config (dict): Check configuration.
        _mutelist (IonosCloudMutelist): Finding filter configuration.
        audit_metadata (Audit_Metadata): Runtime audit counters.
    """

    _type: str = "ionoscloud"
    _session: "ionoscloud.ApiClient"
    _identity: IonosCloudIdentityInfo
    _audit_resources: list = []
    _audit_config: dict
    _fixer_config: dict
    _mutelist: IonosCloudMutelist
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        username: str = None,
        password: str = None,
        token: str = None,
        config_path: str = None,
        config_content: dict = None,
        mutelist_path: str = None,
        mutelist_content: dict = None,
        fixer_config: dict = {},
    ):
        """
        Initialise the IONOS Cloud provider.

        Credentials are resolved in the following priority order:
        1. Explicit ``token`` argument.
        2. ``IONOS_TOKEN`` environment variable.
        3. Explicit ``username`` + ``password`` arguments.
        4. ``IONOS_USERNAME`` + ``IONOS_PASSWORD`` environment variables.

        Args:
            username: IONOS Cloud account email.
            password: IONOS Cloud account password.
            token: IONOS Cloud API token (preferred over username/password).
            config_path: Path to Prowler audit config file.
            config_content: Audit config as a dict (overrides config_path).
            mutelist_path: Path to mutelist YAML file.
            mutelist_content: Mutelist as a dict (overrides mutelist_path).
            fixer_config: Fixer configuration dictionary.

        Raises:
            IonosCloudNoCredentialsError: When no credentials can be found.
            IonosCloudInvalidCredentialsError: When the credentials are rejected.
            IonosCloudSetUpSessionError: On any other session setup failure.
        """
        logger.info("Initializing IONOS Cloud Provider ...")

        # Resolve credentials from arguments or environment
        credentials = self._resolve_credentials(username, password, token)

        # Build authenticated ApiClient
        logger.info("Setting up IONOS Cloud session ...")
        self._session = self.setup_session(credentials)
        logger.info("IONOS Cloud session configured successfully")

        # Validate credentials and populate identity
        logger.info("Validating IONOS Cloud credentials ...")
        self._identity = self.setup_identity(self._session)
        logger.info(f"Authenticated as: {self._identity.user_email}")

        # Audit config
        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

        # Fixer config
        self._fixer_config = fixer_config

        # Mutelist
        if mutelist_content:
            self._mutelist = IonosCloudMutelist(
                mutelist_content=mutelist_content,
                account_id=self._identity.user_id,
            )
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = IonosCloudMutelist(
                mutelist_path=mutelist_path,
                account_id=self._identity.user_id,
            )

        self._audit_resources = []

        self.audit_metadata = Audit_Metadata(
            services_scanned=0,
            expected_checks=[],
            completed_checks=0,
            audit_progress=0,
        )

        Provider.set_global_provider(self)

    # ------------------------------------------------------------------
    # Abstract property implementations
    # ------------------------------------------------------------------

    @property
    def type(self) -> str:
        return self._type

    @property
    def session(self):
        return self._session

    @property
    def identity(self) -> IonosCloudIdentityInfo:
        return self._identity

    @property
    def audit_config(self) -> dict:
        return self._audit_config

    @property
    def fixer_config(self) -> dict:
        return self._fixer_config

    @property
    def audit_resources(self) -> list:
        return self._audit_resources

    @property
    def mutelist(self) -> IonosCloudMutelist:
        return self._mutelist

    # ------------------------------------------------------------------
    # Credential resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_credentials(
        username: str = None,
        password: str = None,
        token: str = None,
    ) -> IonosCloudCredentials:
        """
        Resolve credentials from explicit arguments and environment variables.

        Priority: token > username+password.
        Environment variables: IONOS_TOKEN, IONOS_USERNAME, IONOS_PASSWORD.
        """
        resolved_token = token or os.environ.get("IONOS_TOKEN")
        resolved_username = username or os.environ.get("IONOS_USERNAME")
        resolved_password = password or os.environ.get("IONOS_PASSWORD")

        if not resolved_token and not (resolved_username and resolved_password):
            raise IonosCloudNoCredentialsError(
                file=pathlib.Path(__file__).name,
            )

        return IonosCloudCredentials(
            username=resolved_username,
            password=resolved_password,
            token=resolved_token,
        )

    # ------------------------------------------------------------------
    # Session & identity
    # ------------------------------------------------------------------

    @staticmethod
    def setup_session(credentials: IonosCloudCredentials):
        """
        Build and return a configured ``ionoscloud.ApiClient``.

        Args:
            credentials: Resolved IONOS Cloud credentials.

        Returns:
            ionoscloud.ApiClient ready for use.

        Raises:
            IonosCloudSetUpSessionError: On setup failure.
        """
        try:
            import ionoscloud

            configuration = ionoscloud.Configuration()

            if credentials.token:
                configuration.token = credentials.token
                logger.info("Using IONOS Cloud API token authentication")
            else:
                configuration.username = credentials.username
                configuration.password = credentials.password
                logger.info("Using IONOS Cloud username/password authentication")

            return ionoscloud.ApiClient(configuration)

        except Exception as error:
            logger.critical(
                f"IonosCloudSetUpSessionError[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise IonosCloudSetUpSessionError(
                file=pathlib.Path(__file__).name,
                original_exception=error,
            )

    @staticmethod
    def setup_identity(api_client) -> IonosCloudIdentityInfo:
        """
        Retrieve identity information for the authenticated user.

        Uses ContractResourcesApi to validate credentials (works for all users),
        then derives the user email from the ApiClient configuration.

        Args:
            api_client: Configured ionoscloud.ApiClient.

        Returns:
            IonosCloudIdentityInfo populated with user data.

        Raises:
            IonosCloudInvalidCredentialsError: If the API call fails.
        """
        try:
            import ionoscloud

            # Derive user email from the ApiClient configuration username field.
            # This is always available regardless of account type.
            user_email = getattr(api_client.configuration, "username", "") or ""
            if not user_email:
                user_email = "ionos-token-user"

            account_id = user_email

            # Try API calls to validate credentials and enrich identity.
            # Both may return 400 "No Contract" (error 318) for trial/free accounts
            # whose credentials ARE valid – treat that as a successful auth.
            NO_CONTRACT_CODE = "318"

            try:
                contract_api = ionoscloud.ContractResourcesApi(api_client)
                contract = contract_api.contracts_get(depth=0)
                items = getattr(contract, "items", []) or []
                if items:
                    props = getattr(items[0], "properties", None)
                    if props:
                        contract_number = str(
                            getattr(props, "contract_number", "") or ""
                        )
                        if contract_number:
                            account_id = contract_number
            except ionoscloud.ApiException as api_err:
                body = getattr(api_err, "body", "") or ""
                if NO_CONTRACT_CODE in str(body):
                    logger.warning(
                        "IONOS Cloud account has no Cloud contract. "
                        "Credentials are valid but no resources will be found."
                    )
                else:
                    raise
            except Exception as enrich_error:
                logger.debug(
                    f"Could not retrieve contract info: {enrich_error.__class__.__name__}: {enrich_error}"
                )

            return IonosCloudIdentityInfo(
                user_id=account_id,
                user_email=user_email,
            )

        except ionoscloud.ApiException as error:
            logger.error(
                f"IonosCloudInvalidCredentialsError[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise IonosCloudInvalidCredentialsError(
                file=pathlib.Path(__file__).name,
                original_exception=error,
            )
        except Exception as error:
            logger.error(
                f"IonosCloudInvalidCredentialsError[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise IonosCloudInvalidCredentialsError(
                file=pathlib.Path(__file__).name,
                original_exception=error,
            )

    # ------------------------------------------------------------------
    # CLI display
    # ------------------------------------------------------------------

    def print_credentials(self):
        """Display authenticated identity in the CLI."""
        report_lines = [
            f"IONOS Cloud User: {Fore.YELLOW}{self.identity.user_email}{Style.RESET_ALL}",
            f"User ID: {Fore.YELLOW}{self.identity.user_id}{Style.RESET_ALL}",
        ]
        report_title = (
            f"{Style.BRIGHT}Using the IONOS Cloud credentials below:{Style.RESET_ALL}"
        )
        print_boxes(report_lines, report_title)

    # ------------------------------------------------------------------
    # Connection test
    # ------------------------------------------------------------------

    @staticmethod
    def test_connection(
        username: str = None,
        password: str = None,
        token: str = None,
        raise_on_exception: bool = True,
        provider_id: str = None,
    ) -> Connection:
        """
        Test credentials without creating a full provider instance.

        Args:
            username: IONOS Cloud account email.
            password: IONOS Cloud account password.
            token: IONOS Cloud API token.
            raise_on_exception: Re-raise exceptions when True.
            provider_id: Expected user ID for validation (optional).

        Returns:
            Connection with ``is_connected=True`` on success.
        """
        try:
            credentials = IonoscloudProvider._resolve_credentials(
                username, password, token
            )
            api_client = IonoscloudProvider.setup_session(credentials)
            identity = IonoscloudProvider.setup_identity(api_client)

            if provider_id and identity.user_id != provider_id:
                raise IonosCloudInvalidCredentialsError(
                    file=pathlib.Path(__file__).name,
                    message=f"Provider ID mismatch: expected '{provider_id}', got '{identity.user_id}'",
                )

            logger.info(
                f"Successfully connected to IONOS Cloud as: {identity.user_email}"
            )
            return Connection(is_connected=True)

        except (
            IonosCloudNoCredentialsError,
            IonosCloudInvalidCredentialsError,
            IonosCloudSetUpSessionError,
        ) as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise
            return Connection(error=error)

        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise
            return Connection(error=error)

    def get_checks_to_execute_by_audit_resources(self):
        return set()
