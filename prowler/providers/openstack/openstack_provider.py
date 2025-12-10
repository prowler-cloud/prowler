from os import environ
from typing import Optional

import openstack
from colorama import Fore, Style
from openstack import exceptions as openstack_exceptions
from openstack.connection import Connection as OpenStackConnection

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider
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
            auth_url=auth_url,
            identity_api_version=identity_api_version,
            username=username,
            password=password,
            project_id=project_id,
            region_name=region_name,
            user_domain_name=user_domain_name,
            project_domain_name=project_domain_name,
        )
        self._connection = OpenstackProvider._create_connection(self._session)
        self._identity = OpenstackProvider._build_identity(
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

    @staticmethod
    def setup_session(
        auth_url: Optional[str] = None,
        identity_api_version: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        project_id: Optional[str] = None,
        region_name: Optional[str] = None,
        user_domain_name: Optional[str] = None,
        project_domain_name: Optional[str] = None,
    ) -> OpenStackSession:
        """Collect authentication information from explicit parameters or environment variables."""
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

        resolved_project_id = (
            project_id or environ.get("OS_PROJECT_ID") or environ.get("OS_TENANT_ID")
        )
        if not resolved_project_id:
            missing_variables.append("OS_PROJECT_ID/OS_TENANT_ID")

        if missing_variables:
            pretty_missing = ", ".join(missing_variables)
            raise RuntimeError(
                f"Missing mandatory OpenStack environment variables: {pretty_missing}"
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
    def _create_connection(
        session: OpenStackSession,
    ) -> OpenStackConnection:
        """Initialize the OpenStack SDK connection."""
        try:
            conn = openstack.connect(**session.as_sdk_config())
            conn.authorize()
            return conn
        except openstack_exceptions.SDKException as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- Failed to create OpenStack connection: {error}"
            )
            raise
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- Unexpected error while creating OpenStack connection: {error}"
            )
            raise

    @staticmethod
    def _build_identity(
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
            region_name=session.region_name,
            user_domain_name=session.user_domain_name,
            project_domain_name=session.project_domain_name,
        )

    def test_connection(self) -> Connection:
        try:
            self._connection.authorize()
            return Connection(is_connected=True)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- OpenStack connection test failed: {error}"
            )
            return Connection(is_connected=False, error=error)

    def print_credentials(self) -> None:
        """Output sanitized credential summary."""
        region = self._session.region_name
        auth_url = self._session.auth_url
        project_id = self._session.project_id
        username = self._identity.username
        messages = [
            f"Auth URL: {auth_url}",
            f"Project ID: {project_id}",
            f"Username: {username}",
            f"Region: {region}",
        ]
        print_boxes(messages, "OpenStack Credentials")
        logger.info(
            f"Using OpenStack endpoint {Fore.YELLOW}{auth_url}{Style.RESET_ALL} in region {Fore.YELLOW}{region}{Style.RESET_ALL}"
        )
