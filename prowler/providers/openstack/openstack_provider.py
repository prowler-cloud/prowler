from os import environ
from pathlib import Path
from typing import Optional

from colorama import Fore, Style
from openstack import config, connect
from openstack import exceptions as openstack_exceptions
from openstack.connection import Connection as OpenStackConnection
from yaml import YAMLError, safe_load

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider
from prowler.providers.openstack.exceptions.exceptions import (
    OpenStackAmbiguousRegionError,
    OpenStackAuthenticationError,
    OpenStackCloudNotFoundError,
    OpenStackConfigFileNotFoundError,
    OpenStackCredentialsError,
    OpenStackInvalidConfigError,
    OpenStackInvalidProviderIdError,
    OpenStackNoRegionError,
    OpenStackSessionError,
)
from prowler.providers.openstack.lib.mutelist.mutelist import OpenStackMutelist
from prowler.providers.openstack.models import OpenStackIdentityInfo, OpenStackSession


class OpenstackProvider(Provider):
    """OpenStack provider responsible for bootstrapping the SDK session."""

    _type: str = "openstack"
    _session: OpenStackSession
    _identity: OpenStackIdentityInfo
    _audit_config: dict
    _mutelist: OpenStackMutelist
    _connection: OpenStackConnection
    audit_metadata: Audit_Metadata

    REQUIRED_ENVIRONMENT_VARIABLES = [
        "OS_AUTH_URL",
        "OS_USERNAME",
        "OS_PASSWORD",
        "OS_REGION_NAME",
    ]

    def __init__(
        self,
        clouds_yaml_file: Optional[str] = None,
        clouds_yaml_content: Optional[str] = None,
        clouds_yaml_cloud: Optional[str] = None,
        auth_url: Optional[str] = None,
        identity_api_version: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        project_id: Optional[str] = None,
        region_name: Optional[str] = None,
        user_domain_name: Optional[str] = None,
        project_domain_name: Optional[str] = None,
        config_path: Optional[str] = None,
        config_content: Optional[dict] = None,
        fixer_config: Optional[dict] = None,
        mutelist_path: Optional[str] = None,
        mutelist_content: Optional[dict] = None,
    ) -> None:
        logger.info("Instantiating OpenStack Provider...")

        self._session = self.setup_session(
            clouds_yaml_file=clouds_yaml_file,
            clouds_yaml_content=clouds_yaml_content,
            clouds_yaml_cloud=clouds_yaml_cloud,
            auth_url=auth_url,
            identity_api_version=identity_api_version,
            username=username,
            password=password,
            project_id=project_id,
            region_name=region_name,
            user_domain_name=user_domain_name,
            project_domain_name=project_domain_name,
        )

        # Build per-region connections.  When ``regions`` is configured
        # (multi-region clouds.yaml) we create one connection per region;
        # otherwise a single connection is created.
        if self._session.regions:
            self._regional_connections: dict[str, OpenStackConnection] = {}
            for region in self._session.regions:
                self._regional_connections[region] = (
                    OpenstackProvider._create_connection(self._session, region=region)
                )
            # Default connection = first region (used for identity setup, etc.)
            self._connection = next(iter(self._regional_connections.values()))
        else:
            self._connection = OpenstackProvider._create_connection(self._session)
            self._regional_connections = {self._session.region_name: self._connection}

        self._identity = OpenstackProvider.setup_identity(
            self._connection, self._session
        )

        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

        self._fixer_config = fixer_config or {}

        if mutelist_content:
            self._mutelist = OpenStackMutelist(mutelist_content=mutelist_content)
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = OpenStackMutelist(mutelist_path=mutelist_path)

        Provider.set_global_provider(self)

    @property
    def type(self) -> str:
        return self._type

    @property
    def session(self) -> OpenStackSession:
        return self._session

    @property
    def identity(self) -> OpenStackIdentityInfo:
        return self._identity

    @property
    def audit_config(self) -> dict:
        return self._audit_config

    @property
    def fixer_config(self) -> dict:
        return self._fixer_config

    @property
    def mutelist(self) -> OpenStackMutelist:
        return self._mutelist

    @property
    def connection(self) -> OpenStackConnection:
        return self._connection

    @property
    def regional_connections(self) -> dict[str, OpenStackConnection]:
        return self._regional_connections

    @staticmethod
    def setup_session(
        clouds_yaml_file: Optional[str] = None,
        clouds_yaml_content: Optional[str] = None,
        clouds_yaml_cloud: Optional[str] = None,
        auth_url: Optional[str] = None,
        identity_api_version: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        project_id: Optional[str] = None,
        region_name: Optional[str] = None,
        user_domain_name: Optional[str] = None,
        project_domain_name: Optional[str] = None,
    ) -> OpenStackSession:
        """Collect authentication information from clouds.yaml, explicit parameters, or environment variables.

        Authentication priority:
        1. clouds.yaml content/file (if clouds_yaml_content, clouds_yaml_file, or clouds_yaml_cloud provided)
        2. Explicit parameters + environment variable fallback
        """
        # Priority 1: clouds.yaml authentication
        if clouds_yaml_content:
            logger.info("Using clouds.yaml content string for authentication")
            return OpenstackProvider._setup_session_from_clouds_yaml_content(
                clouds_yaml_content=clouds_yaml_content,
                clouds_yaml_cloud=clouds_yaml_cloud,
            )
        if clouds_yaml_file or clouds_yaml_cloud:
            logger.info("Using clouds.yaml configuration for authentication")
            return OpenstackProvider._setup_session_from_clouds_yaml(
                clouds_yaml_file=clouds_yaml_file,
                clouds_yaml_cloud=clouds_yaml_cloud,
            )

        # Priority 2: Explicit parameters + environment variable fallback (existing behavior)
        provided_overrides = {
            "OS_AUTH_URL": auth_url,
            "OS_USERNAME": username,
            "OS_PASSWORD": password,
            "OS_REGION_NAME": region_name,
        }
        missing_variables = [
            env_var
            for env_var in OpenstackProvider.REQUIRED_ENVIRONMENT_VARIABLES
            if not (provided_overrides.get(env_var) or environ.get(env_var))
        ]

        # Resolve project_id from parameters or environment
        resolved_project_id = project_id or environ.get("OS_PROJECT_ID")

        # OS_PROJECT_ID is mandatory
        if not resolved_project_id:
            missing_variables.append("OS_PROJECT_ID")

        if missing_variables:
            pretty_missing = ", ".join(missing_variables)
            raise OpenStackCredentialsError(
                message=f"Missing mandatory OpenStack environment variables: {pretty_missing}"
            )

        resolved_identity_api_version = (
            identity_api_version or environ.get("OS_IDENTITY_API_VERSION") or "3"
        )
        resolved_user_domain = (
            user_domain_name or environ.get("OS_USER_DOMAIN_NAME") or "Default"
        )
        resolved_project_domain = (
            project_domain_name or environ.get("OS_PROJECT_DOMAIN_NAME") or "Default"
        )

        return OpenStackSession(
            auth_url=auth_url or environ.get("OS_AUTH_URL"),
            identity_api_version=resolved_identity_api_version,
            username=username or environ.get("OS_USERNAME"),
            password=password or environ.get("OS_PASSWORD"),
            project_id=resolved_project_id,
            region_name=region_name or environ.get("OS_REGION_NAME"),
            user_domain_name=resolved_user_domain,
            project_domain_name=resolved_project_domain,
        )

    @staticmethod
    def _setup_session_from_clouds_yaml_content(
        clouds_yaml_content: str,
        clouds_yaml_cloud: Optional[str] = None,
    ) -> OpenStackSession:
        """Setup session from clouds.yaml content provided as a string.

        Parses the YAML content directly instead of writing to a temporary file,
        following the same pattern as KubernetesProvider.setup_session().

        Args:
            clouds_yaml_content: The full YAML content of a clouds.yaml file.
            clouds_yaml_cloud: Cloud name to use from the clouds.yaml content.

        Returns:
            OpenStackSession configured from the provided clouds.yaml content.

        Raises:
            OpenStackInvalidConfigError: If the YAML is malformed or missing required fields.
            OpenStackCloudNotFoundError: If the specified cloud is not found in the content.
        """
        if not clouds_yaml_cloud:
            raise OpenStackInvalidConfigError(
                message="Cloud name (--clouds-yaml-cloud) is required when using clouds.yaml content",
            )

        try:
            parsed = safe_load(clouds_yaml_content)
        except YAMLError as error:
            raise OpenStackInvalidConfigError(
                original_exception=error,
                message=f"Failed to parse clouds.yaml content: {error}",
            )

        if not isinstance(parsed, dict) or "clouds" not in parsed:
            raise OpenStackInvalidConfigError(
                message="Invalid clouds.yaml content: missing 'clouds' key",
            )

        cloud_config = parsed["clouds"].get(clouds_yaml_cloud)
        if not cloud_config:
            raise OpenStackCloudNotFoundError(
                message=f"Cloud '{clouds_yaml_cloud}' not found in clouds.yaml content",
            )

        auth_dict = cloud_config.get("auth", {})

        required_fields = ["auth_url", "username", "password"]
        missing_fields = [
            field for field in required_fields if not auth_dict.get(field)
        ]
        if missing_fields:
            raise OpenStackInvalidConfigError(
                message=f"Missing required fields in clouds.yaml for cloud '{clouds_yaml_cloud}': {', '.join(missing_fields)}",
            )

        # Validate region configuration: must have region_name XOR regions
        region_name = cloud_config.get("region_name")
        regions = cloud_config.get("regions")

        if region_name and regions:
            raise OpenStackAmbiguousRegionError(
                message=f"Cloud '{clouds_yaml_cloud}' has both 'region_name' and 'regions' configured. Use one or the other.",
            )
        if not region_name and not regions:
            raise OpenStackNoRegionError(
                message=f"Cloud '{clouds_yaml_cloud}' has neither 'region_name' nor 'regions' configured. Add one to your clouds.yaml.",
            )

        return OpenStackSession(
            auth_url=auth_dict.get("auth_url"),
            identity_api_version=str(cloud_config.get("identity_api_version", "3")),
            username=auth_dict.get("username"),
            password=auth_dict.get("password"),
            project_id=auth_dict.get("project_id") or auth_dict.get("project_name"),
            region_name=region_name,
            regions=regions,
            user_domain_name=auth_dict.get("user_domain_name", "Default"),
            project_domain_name=auth_dict.get("project_domain_name", "Default"),
        )

    @staticmethod
    def _setup_session_from_clouds_yaml(
        clouds_yaml_file: Optional[str] = None,
        clouds_yaml_cloud: Optional[str] = None,
    ) -> OpenStackSession:
        """Setup session from clouds.yaml configuration file.

        Args:
            clouds_yaml_file: Path to clouds.yaml file. If None, standard locations are searched.
            clouds_yaml_cloud: Cloud name to use from clouds.yaml. Required when using clouds.yaml.

        Returns:
            OpenStackSession configured from clouds.yaml

        Raises:
            OpenStackConfigFileNotFoundError: If clouds.yaml file not found
            OpenStackCloudNotFoundError: If specified cloud not found in clouds.yaml
            OpenStackInvalidConfigError: If clouds.yaml is malformed or missing required fields
        """
        try:
            # Cloud name is required when using clouds.yaml
            if not clouds_yaml_cloud:
                raise OpenStackInvalidConfigError(
                    file=clouds_yaml_file,
                    message="Cloud name (--clouds-yaml-cloud) is required when using clouds.yaml file",
                )

            # Determine config file path
            if clouds_yaml_file:
                # Use explicit path
                config_path = Path(clouds_yaml_file).expanduser()
                if not config_path.exists():
                    raise OpenStackConfigFileNotFoundError(
                        file=str(config_path),
                        message=f"clouds.yaml file not found at {config_path}",
                    )
                logger.info(f"Loading clouds.yaml from {config_path}")
                # Load OpenStack configuration with explicit file
                os_config = config.OpenStackConfig(config_files=[str(config_path)])
            else:
                # Search standard locations if cloud name is provided
                logger.info(
                    "Searching for clouds.yaml in standard locations: "
                    "~/.config/openstack/clouds.yaml, /etc/openstack/clouds.yaml, ./clouds.yaml"
                )
                # Load OpenStack configuration from standard locations (don't pass config_files)
                os_config = config.OpenStackConfig()

            # Get cloud configuration
            logger.info(f"Loading cloud configuration for '{clouds_yaml_cloud}'")

            try:
                cloud_config = os_config.get_one(cloud=clouds_yaml_cloud)
            except openstack_exceptions.OpenStackCloudException as error:
                if "cloud" in str(error).lower() and "not found" in str(error).lower():
                    raise OpenStackCloudNotFoundError(
                        file=clouds_yaml_file,
                        original_exception=error,
                        message=f"Cloud '{clouds_yaml_cloud}' not found in clouds.yaml configuration",
                    )
                raise OpenStackInvalidConfigError(
                    file=clouds_yaml_file,
                    original_exception=error,
                    message=f"Failed to load cloud configuration: {error}",
                )

            # Extract authentication parameters from cloud config
            auth_dict = cloud_config.config.get("auth", {})

            # Validate required fields
            required_fields = ["auth_url", "username", "password"]
            missing_fields = [
                field for field in required_fields if not auth_dict.get(field)
            ]
            if missing_fields:
                raise OpenStackInvalidConfigError(
                    file=clouds_yaml_file,
                    message=f"Missing required fields in clouds.yaml for cloud '{clouds_yaml_cloud}': {', '.join(missing_fields)}",
                )

            # Get raw cloud config to validate region configuration.
            # cloud_config.config is the SDK-processed config (CloudRegion),
            # which may not preserve the 'regions' key. os_config.cloud_config
            # holds the original parsed YAML before SDK processing.
            raw_cloud_config = os_config.cloud_config.get("clouds", {}).get(
                clouds_yaml_cloud, {}
            )

            region_name = raw_cloud_config.get("region_name")
            regions = raw_cloud_config.get("regions")

            if region_name and regions:
                raise OpenStackAmbiguousRegionError(
                    file=clouds_yaml_file,
                    message=f"Cloud '{clouds_yaml_cloud}' has both 'region_name' and 'regions' configured. Use one or the other.",
                )
            if not region_name and not regions:
                raise OpenStackNoRegionError(
                    file=clouds_yaml_file,
                    message=f"Cloud '{clouds_yaml_cloud}' has neither 'region_name' nor 'regions' configured. Add one to your clouds.yaml.",
                )

            # Build OpenStackSession from cloud config
            return OpenStackSession(
                auth_url=auth_dict.get("auth_url"),
                identity_api_version=str(
                    cloud_config.config.get("identity_api_version", "3")
                ),
                username=auth_dict.get("username"),
                password=auth_dict.get("password"),
                project_id=auth_dict.get("project_id") or auth_dict.get("project_name"),
                region_name=region_name,
                regions=regions,
                user_domain_name=auth_dict.get("user_domain_name", "Default"),
                project_domain_name=auth_dict.get("project_domain_name", "Default"),
            )

        except (
            OpenStackConfigFileNotFoundError,
            OpenStackCloudNotFoundError,
            OpenStackInvalidConfigError,
            OpenStackNoRegionError,
            OpenStackAmbiguousRegionError,
        ):
            # Re-raise our custom exceptions
            raise
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "
                f"Failed to load clouds.yaml configuration: {error}"
            )
            raise OpenStackInvalidConfigError(
                file=clouds_yaml_file,
                original_exception=error,
                message=f"Failed to load clouds.yaml configuration: {error}",
            )

    @staticmethod
    def _create_connection(
        session: OpenStackSession,
        region: str | None = None,
    ) -> OpenStackConnection:
        """Initialize the OpenStack SDK connection.

        Note: We explicitly disable loading configuration from clouds.yaml
        and environment variables to ensure Prowler uses only the credentials
        provided through its own configuration mechanisms (CLI args, config file,
        or environment variables read by Prowler itself in setup_session()).

        Args:
            session: The OpenStack session configuration.
            region: Optional region override — when given, the connection is
                scoped to this specific region instead of the session default.
        """
        try:
            # Don't load from clouds.yaml or environment variables, we configure this in setup_session()
            conn = connect(
                load_yaml_config=False,
                load_envvars=False,
                **session.as_sdk_config(region_override=region),
            )
            conn.authorize()
            return conn
        except openstack_exceptions.SDKException as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "
                f"Failed to create OpenStack connection: {error}"
            )
            raise OpenStackAuthenticationError(
                original_exception=error,
                message=f"Failed to create OpenStack connection: {error}",
            )
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- "
                f"Unexpected error while creating OpenStack connection: {error}"
            )
            raise OpenStackSessionError(
                original_exception=error,
                message=f"Unexpected error while creating OpenStack connection: {error}",
            )

    @staticmethod
    def setup_identity(
        conn: OpenStackConnection, session: OpenStackSession
    ) -> OpenStackIdentityInfo:
        """Build identity information for CLI/logging purposes."""
        user_name = session.username
        project_name = None
        user_id = None
        project_id = session.project_id
        try:
            user_id = conn.current_user_id
            if user_id:
                user = conn.identity.get_user(user_id)
                if user and getattr(user, "name", None):
                    user_name = user.name

            project_identifier = conn.current_project_id or session.project_id
            if project_identifier:
                project = conn.identity.get_project(project_identifier)
                if project:
                    project_name = getattr(project, "name", None)
                    project_id = project_identifier
        except openstack_exceptions.SDKException as error:
            logger.warning(f"Unable to enrich OpenStack identity information: {error}")
        except Exception as error:
            logger.warning(f"Unexpected error building OpenStack identity: {error}")

        return OpenStackIdentityInfo(
            user_id=user_id,
            username=user_name,
            project_id=project_id,
            project_name=project_name,
            region_name=session.region_name or ", ".join(session.regions or []),
            user_domain_name=session.user_domain_name,
            project_domain_name=session.project_domain_name,
        )

    @staticmethod
    def test_connection(
        clouds_yaml_file: Optional[str] = None,
        clouds_yaml_content: Optional[str] = None,
        clouds_yaml_cloud: Optional[str] = None,
        auth_url: Optional[str] = None,
        identity_api_version: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        project_id: Optional[str] = None,
        region_name: Optional[str] = None,
        user_domain_name: Optional[str] = None,
        project_domain_name: Optional[str] = None,
        provider_id: Optional[str] = None,
        raise_on_exception: bool = True,
    ) -> Connection:
        """Test connection to OpenStack without creating a full provider instance.

        This static method allows testing OpenStack credentials without initializing
        the entire provider. Useful for API validation before storing credentials.

        Args:
            clouds_yaml_file: Path to clouds.yaml configuration file
            clouds_yaml_content: The full content of a clouds.yaml file as a string
            clouds_yaml_cloud: Cloud name from clouds.yaml to use
            auth_url: OpenStack Keystone authentication URL
            identity_api_version: Keystone API version (default: "3")
            username: OpenStack username
            password: OpenStack password
            project_id: OpenStack project identifier (can be UUID or string ID)
            region_name: OpenStack region name
            user_domain_name: User domain name (default: "Default")
            project_domain_name: Project domain name (default: "Default")
            provider_id: OpenStack provider ID for validation (optional)
            raise_on_exception: Whether to raise exception on failure (default: True)

        Returns:
            Connection object with is_connected=True on success, or error on failure

        Raises:
            OpenStackCredentialsError: If raise_on_exception=True and credentials are invalid
            OpenStackAuthenticationError: If raise_on_exception=True and authentication fails
            OpenStackSessionError: If raise_on_exception=True and connection fails
            OpenStackConfigFileNotFoundError: If raise_on_exception=True and clouds.yaml not found
            OpenStackCloudNotFoundError: If raise_on_exception=True and cloud not in clouds.yaml
            OpenStackInvalidConfigError: If raise_on_exception=True and clouds.yaml is malformed

        Examples:
            >>> # Test with explicit credentials
            >>> OpenstackProvider.test_connection(
            ...     auth_url="https://openstack.example.com:5000/v3",
            ...     username="admin",
            ...     password="secret",
            ...     project_id="my-project-id",
            ...     region_name="RegionOne"
            ... )
            Connection(is_connected=True, error=None)

            >>> # Test with clouds.yaml
            >>> OpenstackProvider.test_connection(
            ...     clouds_yaml_file="~/.config/openstack/clouds.yaml",
            ...     clouds_yaml_cloud="production"
            ... )
            Connection(is_connected=True, error=None)
        """
        try:
            # Setup session with provided credentials
            session = OpenstackProvider.setup_session(
                clouds_yaml_file=clouds_yaml_file,
                clouds_yaml_content=clouds_yaml_content,
                clouds_yaml_cloud=clouds_yaml_cloud,
                auth_url=auth_url,
                identity_api_version=identity_api_version,
                username=username,
                password=password,
                project_id=project_id,
                region_name=region_name,
                user_domain_name=user_domain_name,
                project_domain_name=project_domain_name,
            )

            # Validate provider_id matches project_id from config
            if provider_id and session.project_id != provider_id:
                raise OpenStackInvalidProviderIdError(
                    message=f"Provider ID '{provider_id}' does not match project_id '{session.project_id}' from clouds.yaml",
                )

            # Create and test connection(s) — one per region when multi-region
            if session.regions:
                for region in session.regions:
                    OpenstackProvider._create_connection(session, region=region)
            else:
                OpenstackProvider._create_connection(session)

            logger.info("OpenStack provider: Connection test successful")
            return Connection(is_connected=True)

        except (
            OpenStackCredentialsError,
            OpenStackAuthenticationError,
            OpenStackSessionError,
            OpenStackConfigFileNotFoundError,
            OpenStackCloudNotFoundError,
            OpenStackInvalidConfigError,
            OpenStackInvalidProviderIdError,
            OpenStackNoRegionError,
            OpenStackAmbiguousRegionError,
        ) as error:
            logger.error(f"OpenStack connection test failed: {error}")
            if raise_on_exception:
                raise
            return Connection(is_connected=False, error=error)
        except Exception as error:
            logger.error(
                f"OpenStack connection test failed with unexpected error: {error}"
            )
            if raise_on_exception:
                raise OpenStackSessionError(
                    original_exception=error,
                    message=f"Unexpected error during connection test: {error}",
                )
            return Connection(is_connected=False, error=error)

    def print_credentials(self) -> None:
        """Output sanitized credential summary."""
        auth_url = self._session.auth_url
        project_id = self._session.project_id
        username = self._identity.username

        if self._session.regions:
            region_display = ", ".join(self._session.regions)
        else:
            region_display = self._session.region_name

        messages = [
            f"Auth URL: {auth_url}",
            f"Project ID: {project_id}",
            f"Username: {username}",
            f"Region: {region_display}",
        ]
        print_boxes(messages, "OpenStack Credentials")
        logger.info(
            f"Using OpenStack endpoint {Fore.YELLOW}{auth_url}{Style.RESET_ALL} "
            f"in region {Fore.YELLOW}{region_display}{Style.RESET_ALL}"
        )
