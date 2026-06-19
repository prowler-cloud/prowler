import os

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
from prowler.providers.e2e.exceptions.exceptions import (
    E2eCredentialsError,
    E2eSessionError,
)
from prowler.providers.e2e.lib.mutelist.mutelist import E2eMutelist
from prowler.providers.e2e.models import (
    E2E_DEFAULT_LOCATIONS,
    E2eIdentityInfo,
    E2eSession,
)


class E2eProvider(Provider):
    """Provider class for E2E Cloud."""

    _type: str = "e2e"
    _session: E2eSession
    _identity: E2eIdentityInfo
    _audit_config: dict
    _fixer_config: dict
    _mutelist: E2eMutelist
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        api_key: str = None,
        auth_token: str = None,
        project_id: str | int = None,
        locations: list[str] | None = None,
        config_path: str = None,
        fixer_config: dict = None,
        mutelist_path: str = None,
        mutelist_content: dict = None,
    ):
        logger.info("Initializing E2E Cloud Provider...")

        self._api_key = api_key or os.getenv("E2E_API_KEY")
        self._auth_token = auth_token or os.getenv("E2E_AUTH_TOKEN")
        project_value = project_id or os.getenv("E2E_PROJECT_ID")
        self._project_id = int(project_value) if project_value else None
        self._locations = self._resolve_locations(locations)

        if not self._api_key or not self._auth_token or self._project_id is None:
            raise E2eCredentialsError(
                "E2eProvider requires api_key, auth_token, and project_id."
            )

        self._fixer_config = fixer_config if fixer_config else {}
        if not config_path:
            config_path = default_config_file_path
        self._audit_config = load_and_validate_config_file(self._type, config_path)

        if mutelist_content:
            self._mutelist = E2eMutelist(mutelist_content=mutelist_content)
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self._type)
            self._mutelist = E2eMutelist(mutelist_path=mutelist_path)

        self._session = E2eProvider.setup_session(
            api_key=self._api_key,
            auth_token=self._auth_token,
            project_id=self._project_id,
            locations=self._locations,
        )
        self._identity = E2eIdentityInfo(
            project_id=self._project_id,
            locations=self._locations,
        )

        Provider.set_global_provider(self)

    @staticmethod
    def _resolve_locations(locations: list[str] | None) -> list[str]:
        if locations:
            return locations

        env_location = os.getenv("E2E_LOCATION")
        if env_location:
            return [env_location]

        return list(E2E_DEFAULT_LOCATIONS)

    @property
    def type(self) -> str:
        return self._type

    @property
    def session(self) -> E2eSession:
        return self._session

    @property
    def identity(self) -> E2eIdentityInfo:
        return self._identity

    @property
    def audit_config(self) -> dict:
        return self._audit_config

    @property
    def fixer_config(self) -> dict:
        return self._fixer_config

    @property
    def mutelist(self) -> E2eMutelist:
        return self._mutelist

    @staticmethod
    def setup_session(
        api_key: str,
        auth_token: str,
        project_id: int,
        locations: list[str],
    ) -> E2eSession:
        try:
            http_session = requests.Session()
            http_session.headers.update(
                {
                    "Authorization": f"Bearer {auth_token}",
                    "Content-Type": "application/json",
                }
            )
            return E2eSession(
                api_key=api_key,
                auth_token=auth_token,
                project_id=project_id,
                locations=locations,
                http_session=http_session,
            )
        except Exception as error:
            raise E2eSessionError(
                message="Failed to initialize E2E Cloud session.",
                original_exception=error,
            ) from error

    def print_credentials(self) -> None:
        masked_key = (
            f"{self._api_key[:4]}...{self._api_key[-4:]}"
            if self._api_key and len(self._api_key) > 8
            else "****"
        )
        report_lines = [
            f"  Project ID: {self._project_id}",
            f"  Locations: {', '.join(self._locations)}",
            f"  API Key: {masked_key}",
        ]
        report_title = (
            f"{Style.BRIGHT}Using the E2E Cloud credentials below:{Style.RESET_ALL}"
        )
        print_boxes(report_lines, report_title)

    @staticmethod
    def test_connection(
        api_key: str = None,
        auth_token: str = None,
        project_id: str | int = None,
        locations: list[str] | None = None,
        raise_on_exception: bool = True,
    ) -> Connection:
        try:
            api_key = api_key or os.getenv("E2E_API_KEY")
            auth_token = auth_token or os.getenv("E2E_AUTH_TOKEN")
            project_value = project_id or os.getenv("E2E_PROJECT_ID")
            project_id_int = int(project_value) if project_value else None
            resolved_locations = locations or (
                [os.getenv("E2E_LOCATION")]
                if os.getenv("E2E_LOCATION")
                else list(E2E_DEFAULT_LOCATIONS)
            )

            if not api_key or not auth_token or project_id_int is None:
                raise E2eCredentialsError(
                    "E2E Cloud test_connection requires api_key, auth_token, and project_id."
                )

            session = E2eProvider.setup_session(
                api_key=api_key,
                auth_token=auth_token,
                project_id=project_id_int,
                locations=resolved_locations,
            )
            response = session.http_session.get(
                f"{session.base_url}/nodes/",
                params={
                    "apikey": session.api_key,
                    "project_id": session.project_id,
                    "location": resolved_locations[0],
                },
                timeout=30,
            )
            if response.status_code != 200:
                error_msg = (
                    f"E2E Cloud connection failed with status {response.status_code}: "
                    f"{response.text}"
                )
                raise E2eSessionError(message=error_msg)

            return Connection(is_connected=True)
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise error
            return Connection(error=error)
