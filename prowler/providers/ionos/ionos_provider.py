import sys
import json
import os
import subprocess
from typing import Any, Optional, Tuple

import ionoscloud
from ionoscloud import ApiClient, Configuration
from ionoscloud.rest import ApiException
import ionoscloud_dataplatform
from ionoscloud.api.data_centers_api import DataCentersApi
from ionoscloud.api.user_management_api import UserManagementApi

from prowler.config.config import get_default_mute_file_path, load_and_validate_config_file
from prowler.lib.logger import logger
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.providers.ionos.lib.mutelist.mutelist import IonosMutelist
from prowler.providers.ionos.models import IonosIdentityInfo
from prowler.lib.utils.utils import open_file, parse_json_file, print_boxes
from prowler.providers.ionos.exceptions.exceptions import (
    IonosNoAuthMethodProvidedError,
    IonosIncompleteCredentialsError,
    IonosEnvironmentCredentialsError,
    IonosTokenLoadError,
)
from colorama import Fore, Style

from prowler.providers.common.provider import Provider

class IonosProvider(Provider):
    _type: str = "ionos"
    _session: Optional[ApiClient] = None
    _identity: Optional[IonosIdentityInfo] = None
    _audit_config: dict = {}
    _output_options: Optional[Any] = None
    _mutelist: IonosMutelist
    audit_metadata: Optional[Any] = None
    _token = None
    _username = None
    _password = None
    _datacenter_id = None

    def __init__(
        self,
        ionos_username: Optional[str] = None,
        ionos_password: Optional[str] = None,
        ionos_datacenter_name: Optional[str] = None,
        config_path: Optional[str] = None,
        mutelist_path: Optional[str] = None,
        mutelist_content: dict = None,
        use_ionosctl: bool = False,
        use_env_vars: bool = False,
    ):
        """
        Initializes the IonosProvider class and sets up the session.

        Args:
            ionos_username (Optional[str]): Static username for IONOS authentication
            ionos_password (Optional[str]): Static password for IONOS authentication
            ionos_datacenter_name (Optional[str]): Name of the datacenter to use
            config_path (Optional[str]): Path to the configuration file
            mutelist_path (Optional[str]): Path to the mutelist file
            mutelist_content (dict): Mutelist content as dictionary
            use_ionosctl (bool): Whether to use ionosctl token authentication
            use_env_vars (bool): Whether to use environment variables for authentication

        Raises:
            IonosNoAuthMethodProvidedError: When no authentication method is provided
            IonosIncompleteCredentialsError: When username/password credentials are incomplete
            IonosEnvironmentCredentialsError: When environment credentials are incomplete
            IonosTokenLoadError: When ionosctl token cannot be loaded
        """
        logger.info("Initializing IONOS Provider...")

        self._token = None
        self._username = None
        self._password = None
        self._datacenter_name = ionos_datacenter_name

        if not any([use_ionosctl, use_env_vars, all([ionos_username, ionos_password])]):
            raise IonosNoAuthMethodProvidedError()

        if use_ionosctl:
            self._token = self.load_ionosctl_token()
            if not self._token:
                raise IonosTokenLoadError()
            logger.info("Using ionosctl token authentication")

        elif use_env_vars:
            self._username = os.getenv("IONOS_USERNAME")
            self._password = os.getenv("IONOS_PASSWORD")
            if not all([self._username, self._password]):
                raise IonosEnvironmentCredentialsError()
            logger.info("Using environment variables authentication")

        elif ionos_username or ionos_password:
            if not all([ionos_username, ionos_password]):
                raise IonosIncompleteCredentialsError()
            self._username = ionos_username
            self._password = ionos_password
            logger.info("Using static credentials authentication")

        temp_identity = IonosIdentityInfo(
            username=self._username,
            password=self._password,
            datacenter_id="",
            token=self._token,
        )

        self._session = self.setup_session(
            identity=temp_identity,
        )

        if not self.test_connection():
            logger.critical("Failed to establish connection with IONOS Cloud API, please check your credentials.")
            sys.exit(1)

        self._identity = self.setup_identity(
            username=self._username,
            password=self._password,
            datacenter_id="",
        )

        if config_path is None:
            self._audit_config = {}
        else:
            self._audit_config = load_and_validate_config_file("ionos", config_path)
        
        if mutelist_content:
            self._mutelist = IonosMutelist(
                mutelist_content=mutelist_content,
            )
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
                logger.info(f"No mutelist path provided, using default: {mutelist_path}")
            self._mutelist = IonosMutelist(
                mutelist_path=mutelist_path,
            )
            logger.info(f"Loaded mutelist from {mutelist_path}")

        Provider.set_global_provider(self)

    @staticmethod
    def load_env_credentials() -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Reads IONOS credentials from environment variables.
        Returns a tuple with (username, password, token)
        """
        username = os.getenv("IONOS_USERNAME")
        password = os.getenv("IONOS_PASSWORD")
        token = os.getenv("IONOS_TOKEN")
        if username and password and token:
            logger.info("Loaded IONOS credentials from environment variables.")
        else:
            logger.warning("Not all credentials were found in environment variables.")
        return username, password, token

    @staticmethod
    def load_ionosctl_token() -> Optional[str]:
        """
        Reads the IONOS token from the ionosctl configuration file across different platforms.

        Returns:
            Optional[str]: The IONOS token if found, None otherwise

        Raises:
            IonosTokenLoadError: If the token cannot be loaded from the configuration
        """
        platform = sys.platform
        
        is_wsl = False
        try:
            with open('/proc/version') as f:
                is_wsl = 'microsoft' in f.read().lower()
        except:
            pass

        config_paths = {
            "darwin": os.path.join(os.path.expanduser("~"), "Library", "Application Support", "ionosctl", "config.json"),
            "linux": os.path.join(os.getenv("XDG_CONFIG_HOME", os.path.expanduser("~/.config")), "ionosctl", "config.json"),
            "win32": os.path.join(os.getenv("APPDATA", ""), "ionosctl", "config.json")
        }
        
        if is_wsl:
            try:
                windows_config = "/mnt/c/Users/{}/AppData/Roaming/ionosctl/config.json".format(
                    os.getenv("USER")
                )
                try:
                    with open(windows_config, "r") as config_file:
                        config = json.load(config_file)
                        logger.info("Loaded IONOS token from Windows ionosctl config file in WSL.")
                        return config.get("userdata.token")
                except Exception as e:
                    logger.debug(f"Could not load Windows config file in WSL, trying Linux path... {e}")
            except Exception as e:
                logger.debug(f"Failed to access Windows config file: {e}")
        
        config_path = config_paths.get(platform)
        
        if not config_path:
            logger.warning(f"Unsupported platform: {platform}")
            return None
            
        try:
            with open(config_path, "r") as config_file:
                config = json.load(config_file)
                token = config.get("userdata.token")
                if token:
                    logger.info("Loaded IONOS token from ionosctl config file.")
                    return token
                raise IonosTokenLoadError()
        except (FileNotFoundError, json.JSONDecodeError) as error:
            logger.warning(f"Failed to load IONOS token from ionosctl: {error}")
            raise IonosTokenLoadError()

    def get_ionos_username(self) -> Optional[str]:
        """
        Gets the IONOS username from the API.
        """
        user_api = UserManagementApi(self._session)
        try:
            user = user_api.um_users_get(depth=1).items[0]
            return user.properties.email
        except ApiException as error:
            logger.error(f"Failed to retrieve user information: {error}")
            sys.exit(1)

    @property
    def type(self) -> str:
        return self._type

    @property
    def identity(self) -> str:
        return self._identity

    @property
    def session(self) -> ApiClient:
        return self._session

    @property
    def audit_config(self) -> dict:
        return self._audit_config

    @property
    def mutelist(self) -> IonosMutelist:
        """
        mutelist method returns the provider's mutelist
        """
        return self._mutelist
    
    @property
    def session(self) -> ApiClient:
        return self._session

    def setup_session(
        self, 
        identity: IonosIdentityInfo,
    ) -> ApiClient:
        """
        Setup the session to interact with the IONOS Cloud API.
        """
        try:
            config = Configuration()

            config.username = identity.username
            config.password = identity.password
            config.token = identity.token

            logger.info("Successfully initialized IONOS Cloud API session.")
            return ApiClient(configuration=config)
        except Exception as error:
            logger.critical(f"Failed to initialize IONOS session: {error}")
            sys.exit(1)

    def print_credentials(self) -> None:     
        """
        Print the IONOS Cloud credentials.

        This method prints the IONOS Cloud credentials used by the provider.
        """

        username = self._session.configuration.username
        host = self._session.configuration.host
        if self._identity.token:
            if len(self._identity.token) > 8:
                masked_token = self._identity.token[:4] + "*" * 16 + self._identity.token[-4:]
            else:
                masked_token = self._identity.token
        else:
            masked_token = "Not Provided"

        datacenters = self.get_datacenters()

        datacenter_id = datacenters[0].id if datacenters else "Not Found"
        datacenter_name = datacenters[0].properties.name if datacenters else "Not Found"
        datacenter_location = datacenters[0].properties.location if datacenters else "Not Found"

        report_lines = [
            f"Datacenter ID: {Fore.YELLOW}{datacenter_id}{Style.RESET_ALL}",
            f"Datacenter Name: {Fore.YELLOW}{datacenter_name}{Style.RESET_ALL}",
            f"Datacenter Location: {Fore.YELLOW}{datacenter_location}{Style.RESET_ALL}",
        ]
        report_title = f"{Style.BRIGHT}Using the IONOS Cloud credentials below:{Style.RESET_ALL}"
        print_boxes(report_lines, report_title)

    def get_datacenter_id(self, datacenter_name: Optional[str] = None) -> str:
        """
        Gets the ID of a datacenter by its name.
        If the name is empty or None, returns the first available datacenter.
        """
        datacenters = self.get_datacenters()
        
        if not datacenter_name:
            return datacenters[0].id if datacenters else ""
        
        for datacenter in datacenters:
            if datacenter.properties.name == datacenter_name:
                return datacenter.id
        return ""

    def set_datacenter(self, datacenter_id: str) -> None:
        """
        Sets the active datacenter for operations.
        """
        self._identity.datacenter_id = datacenter_id

    def test_connection(self) -> bool:
        """
        Tests the connection with the IONOS API.
        """
        try:
            datacenter_api = DataCentersApi(self._session)
            datacenters = datacenter_api.datacenters_get()
            logger.info("Successfully connected to IONOS Cloud API.")
            return True
        except ApiException as error:
            return False

    def get_datacenters(self) -> list:
        """
        Retrieves the list of datacenters from the IONOS account.
        """
        try:
            datacenter_api = ionoscloud.DataCentersApi(self._session)
            datacenters = datacenter_api.datacenters_get(pretty=True, depth=1).items
            logger.info("Successfully retrieved datacenters from IONOS Cloud API.")
            return datacenters
        except ApiException as error:
            logger.error(f"Failed to retrieve datacenters from IONOS Cloud API: {error}")
            return []

    def setup_identity(
        self,
        username: str,
        password: str,
        datacenter_id: str,
    ) -> IonosIdentityInfo:
        """
        Sets up the IONOS provider identity information.

        First tries to create identity with provided credentials.
        If username is not available, attempts to fetch it from the API.
        Finally sets up the datacenter ID.

        Args:
            username (str): The username for authentication
            password (str): The password for authentication
            datacenter_id (str): The datacenter ID

        Returns:
            IonosIdentityInfo: The configured identity information
        """
        identity = IonosIdentityInfo(
            username=username,
            password=password,
            datacenter_id=datacenter_id,
            token=self._token,
        )

        if not identity.username:
            identity.username = self.get_ionos_username()

        identity.datacenter_id = self.get_datacenter_id(self._datacenter_name)

        return identity

    def validate_mutelist_content(self, content: dict) -> bool:
        """Validates the format of the mutelist content"""
        if not isinstance(content, dict):
            return False
        if "muted_checks" not in content:
            return False
        if not isinstance(content["muted_checks"], list):
            return False
        return True