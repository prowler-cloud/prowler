import os
from typing import Optional

import requests
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
from prowler.providers.nhn.lib.mutelist.mutelist import NHNMutelist
from prowler.providers.nhn.models import NHNIdentityInfo


class NhnProvider(Provider):
    """
    NHN Provider class to handle the NHN provider

    Attributes:
    - _type: str -> The type of the provider, which is set to "nhn".
    - _session: requests.Session -> The session object associated with the NHN provider.
    - _identity: NHNIdentityInfo -> The identity information for the NHN provider.
    - _audit_config: dict -> The audit configuration for the NHN provider.
    - _mutelist: NHNMutelist -> The mutelist object associated with the NHN provider.
    - audit_metadata: Audit_Metadata -> The audit metadata for the NHN provider.

    Methods:
    - __init__: Initializes the NHN provider.
    - type: Returns the type of the NHN provider.
    - identity: Returns the identity of the NHN provider.(ex: tenant_id, username)
    - session: Returns the session object associated with the NHN provider.(ex: Bearer token)
    - audit_config: Returns the audit configuration for the NHN provider.
    - fixer_config: Returns the fixer configuration.
    - mutelist: Returns the mutelist object associated with the NHN provider.
    - validate_arguments: Validates the NHN provider arguments.(ex: username, password, tenant_id)
    - print_credentials: Prints the NHN credentials information.(ex: username, tenant_id)
    - setup_session: Set up the NHN session with the specified authentication method.
    - test_connection: tests the provider connection
    """

    _type: str = "nhn"
    _session: Optional[requests.Session]
    _identity: NHNIdentityInfo
    _audit_config: dict
    _mutelist: NHNMutelist
    # TODO: this is not optional, enforce for all providers
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        username: str = None,
        password: str = None,
        tenant_id: str = None,
        config_path: str = None,
        fixer_config: dict = None,
        mutelist_path: str = None,
        mutelist_content: dict = None,
    ):
        """
        Initializes the NHN provider.

        Args:
            - username: The NHN Cloud client ID
            - password: The NHN Cloud client password
            - tenant_id: The NHN Cloud Tenant ID
            - config_path: The path to the configuration file.
            - fixer_config: The fixer configuration.
            - mutelist_path: The path to the mutelist file.
            - mutelist_content: The mutelist content.
        """
        logger.info("Initializing Nhn Provider...")

        # 1) Store argument values
        self._username = username or os.getenv("NHN_USERNAME")
        self._password = password or os.getenv("NHN_PASSWORD")
        self._tenant_id = tenant_id or os.getenv("NHN_TENANT_ID")

        if not all([self._username, self._password, self._tenant_id]):
            raise ValueError("NhnProvider requires username, password and tenant_id")

        # 2) Load audit_config, fixer_config, mutelist
        self._fixer_config = fixer_config if fixer_config else {}
        if not config_path:
            config_path = default_config_file_path
        self._audit_config = load_and_validate_config_file(self._type, config_path)

        if mutelist_content:
            self._mutelist = NHNMutelist(mutelist_content=mutelist_content)
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self._type)
            self._mutelist = NHNMutelist(mutelist_path=mutelist_path)

        # 3) Initialize session/token
        self._token = None
        self._session = None
        self.setup_session()

        # 4) Create NHNIdentityInfo object
        self._identity = NHNIdentityInfo(
            tenant_id=self._tenant_id,
            username=self._username,
        )

        Provider.set_global_provider(self)

    @property
    def type(self) -> str:
        """
        Returns the type of the provider ("nhn").
        """
        return self._type

    @property
    def identity(self) -> str:
        """
        Returns the NHNIdentityInfo object, which may contain tenant_id, username, etc.
        """
        return self._identity

    @property
    def session(self) -> str:
        """
        Returns the requests.Session object for NHN API calls.
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
        Returns any fixer configuration provided to the NHN provider.
        """
        return self._fixer_config

    @property
    def mutelist(self) -> dict:
        """
        Returns the NHNMutelist object for handling any muted checks.
        """
        return self._mutelist

    @staticmethod
    def validate_arguments(username: str, password: str, tenant_id: str) -> None:
        """
        Ensures that username, password, and tenant_id are not empty.
        """
        if not username or not password or not tenant_id:
            raise ValueError("NHN Provider requires username, password and tenant_id.")

    def print_credentials(self) -> None:
        """
        Prints the NHN credentials in a simple box format.
        """
        report_lines = [
            f"  Username: {self._username}",
            f"  TenantID: {self._tenant_id}",
        ]
        report_title = (
            f"{Style.BRIGHT}Using the NHN credentials below:{Style.RESET_ALL}"
        )
        print_boxes(report_lines, report_title)

    def setup_session(self) -> None:
        """
        Implement NHN Cloud Authentication method by calling Keystone v2.0 API(POST /v2.0/tokens).
        ex) https://api-identity-infrastructure.nhncloudservice.com/v2.0/tokens
        {
            "auth": {
                "tenantId": "f5073eaa26b64cffbee89411df94ce01",
                "passwordCredentials": {
                    "username": "user@example.com",
                    "password": "secretsecret"
                }
            }
        }

        On success, it creates a requests.Session and sets the X-Auth-Token header.
        """
        url = "https://api-identity-infrastructure.nhncloudservice.com/v2.0/tokens"
        data = {
            "auth": {
                "tenantId": self._tenant_id,
                "passwordCredentials": {
                    "username": self._username,
                    "password": self._password,
                },
            }
        }
        try:
            response = requests.post(url, json=data, timeout=10)
            if response.status_code == 200:
                resp_json = response.json()
                self._token = resp_json["access"]["token"]["id"]
                sess = requests.Session()
                sess.headers.update(
                    {"X-Auth-Token": self._token, "Content-Type": "application/json"}
                )
                self._session = sess
                logger.info("NHN token acquired successfully and session is set up.")
            else:
                logger.critical(
                    f"Failed to get token. Status: {response.status_code}, Body: {response.text}"
                )
                raise ValueError("Failed to get NHN token")
        except Exception as e:
            logger.critical(f"[setup_session] Error: {e}")
            raise e

    @staticmethod
    def test_connection(
        username: str,
        password: str,
        tenant_id: str,
        raise_on_exception: bool = True,
    ) -> Connection:
        """
        Test connection to NHN Cloud by performing:
          1) Keystone token request
          2) (Optional) a small test API call to confirm credentials are valid

        Args:
            username (str): NHN Cloud user ID (email)
            password (str): NHN Cloud user password
            tenant_id (str): NHN Cloud tenant ID
            raise_on_exception (bool): If True, raise the caught exception;
                                       if False, return Connection(error=exception).

        Returns:
            Connection:
                Connection(is_connected=True) if success,
                otherwise Connection(error=Exception or custom error).
        """
        try:
            # 1) Validate arguments (예: username/password/tenant_id)
            if not username or not password or not tenant_id:
                error_msg = (
                    "NHN test_connection error: missing username/password/tenant_id"
                )
                logger.exception(error_msg)
                raise ValueError(error_msg)

            # 2) Request Keystone token
            token_url = (
                "https://api-identity-infrastructure.nhncloudservice.com/v2.0/tokens"
            )
            data = {
                "auth": {
                    "tenantId": tenant_id,
                    "passwordCredentials": {
                        "username": username,
                        "password": password,
                    },
                }
            }
            resp = requests.post(token_url, json=data, timeout=10)
            if resp.status_code != 200:
                # Fail
                error_msg = f"Failed to get token. Status: {resp.status_code}, Body: {resp.text}"
                logger.exception(error_msg)
                if raise_on_exception:
                    raise Exception(error_msg)
                return Connection(error=Exception(error_msg))

            # Success
            token_json = resp.json()
            keystone_token = token_json["access"]["token"]["id"]
            logger.info("NHN test_connection: Successfully acquired Keystone token.")

            # 3) (Optional) Test API call to confirm credentials are valid
            compute_endpoint = f"https://kr1-api-instance.infrastructure.cloud.toast.com/v2/{tenant_id}"

            # Check servers list
            headers = {
                "X-Auth-Token": keystone_token,
                "Content-Type": "application/json",
            }
            servers_resp = requests.get(
                f"{compute_endpoint}/servers", headers=headers, timeout=10
            )
            if servers_resp.status_code == 200:
                logger.info(
                    "NHN test_connection: /servers call success. Credentials valid."
                )
                return Connection(is_connected=True)
            else:
                error_msg = f"/servers call failed. Status: {servers_resp.status_code}, Body: {servers_resp.text}"
                logger.exception(error_msg)
                if raise_on_exception:
                    raise Exception(error_msg)
                return Connection(error=Exception(error_msg))

        except Exception as e:
            logger.critical(f"{e.__class__.__name__}[{e.__traceback__.tb_lineno}]: {e}")
            if raise_on_exception:
                raise e
            return Connection(error=e)
