import sys
import json
import os
from abc import ABC, abstractmethod
from argparse import Namespace
from typing import Any, Optional

import ionoscloud
from ionoscloud import ApiClient, Configuration
from ionoscloud.rest import ApiException
import ionoscloud_dataplatform

from prowler.config.config import load_and_validate_config_file
from prowler.lib.logger import logger
from prowler.lib.mutelist.mutelist import Mutelist

class IonosProvider(ABC):
    _global: Optional["IonosProvider"] = None
    _type: str = "ionos"
    _session: Optional[ApiClient] = None
    _identity: Optional[str] = None
    _audit_config: dict = {}
    _output_options: Optional[Any] = None
    _mutelist: Optional[Mutelist] = None
    audit_metadata: Optional[Any] = None

    def __init__(self, username: Optional[str] = None, password: Optional[str] = None, config_path: Optional[str] = None, mutelist_path: Optional[str] = None):
        """
        Initializes the IonosProvider class and sets up the session.
        If no credentials are provided, attempts to load them from environment variables or ionosctl config.
        """
        logger.info("Initializing IONOS Provider...")
        self._identity = username
        self._audit_config = load_and_validate_config_file("ionos", config_path)
        self._mutelist = Mutelist(mutelist_path) if mutelist_path else None
        
        # Load credentials from environment variables or ionosctl config if not provided
        if not username or not password:
            username, password, token = self.load_env_credentials()
        #if not username or not password:
        #    username, password = self.load_ionosctl_credentials()
        
        self.setup_session(username, password, token)

    @staticmethod
    def load_env_credentials() -> tuple[Optional[str], Optional[str]]:
        """
        Reads IONOS credentials from environment variables.
        """
        username = os.getenv("IONOS_USERNAME")
        password = os.getenv("IONOS_PASSWORD")
        token = os.getenv("IONOS_TOKEN")
        if username and password and token:
            logger.info("Loaded IONOS credentials from environment variables.")
        return username, password, token

    @staticmethod
    def load_ionosctl_credentials() -> tuple[Optional[str], Optional[str]]:
        """
        Reads IONOS credentials from ionosctl configuration file.
        """
        config_path = os.path.expanduser("~/.config/ionosctl/config.json")
        try:
            with open(config_path, "r") as config_file:
                config = json.load(config_file)
                logger.info("Loaded IONOS credentials from ionosctl config file.")
                return config.get("username"), config.get("password")
        except (FileNotFoundError, json.JSONDecodeError) as error:
            logger.warning(f"Failed to load IONOS credentials from ionosctl: {error}")
            return None, None

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

    def setup_session(self, username: str, password: str, token: str):
        """
        Configures the session for interacting with the IONOS Cloud API.
        """
        try:
            config = ionoscloud_dataplatform.Configuration(username=username, password=password, token=token)
            self._session = ionoscloud_dataplatform.ApiClient(configuration=config)
            logger.info("Successfully initialized IONOS Cloud API session.")
        except Exception as error:
            logger.critical(f"Failed to initialize IONOS session: {error}")
            sys.exit(1)

    def print_credentials(self) -> None:
        """
        Prints the identity of the provider.
        """
        logger.info(f"IONOS Provider Identity: {self._identity}")

    def test_connection(self) -> bool:
        """
        Tests the connection to the IONOS API.
        """
        try:
            datacenter_api = ionoscloud.DataCenterApi(self._session)
            datacenters = datacenter_api.datacenters_get()
            logger.info("Successfully connected to IONOS Cloud API.")
            return True
        except ApiException as error:
            logger.error(f"Failed to connect to IONOS Cloud API: {error}")
            return False

    @staticmethod
    def get_global_provider() -> "IonosProvider":
        return IonosProvider._global

    @staticmethod
    def set_global_provider(global_provider: "IonosProvider") -> None:
        IonosProvider._global = global_provider
