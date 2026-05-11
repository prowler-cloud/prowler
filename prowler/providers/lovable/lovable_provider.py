"""Lovable Provider.

Authenticates against the Lovable Cloud API using a workspace-scoped API
token, optionally augments findings with Supabase posture data, and exposes
projects + their published apps for security assessment.
"""

import os

import requests
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
from prowler.providers.lovable.config import (
    LOVABLE_API_BASE_URL,
    LOVABLE_API_VERSION,
    LOVABLE_DEFAULT_TIMEOUT,
    LOVABLE_USER_AGENT,
)
from prowler.providers.lovable.exceptions.exceptions import (
    LovableAuthenticationError,
    LovableCredentialsError,
    LovableIdentityError,
    LovableInvalidProviderIdError,
    LovableInvalidWorkspaceError,
    LovableRateLimitError,
    LovableSessionError,
)
from prowler.providers.lovable.lib.mutelist.mutelist import LovableMutelist
from prowler.providers.lovable.models import (
    LovableIdentityInfo,
    LovableSession,
    LovableWorkspaceInfo,
)


class LovableProvider(Provider):
    """Provider for Lovable AI app builder workspaces and published apps."""

    _type: str = "lovable"
    _session: LovableSession
    _identity: LovableIdentityInfo
    _audit_config: dict
    _fixer_config: dict
    _mutelist: LovableMutelist
    _filter_projects: set[str] | None
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        # Authentication
        api_token: str | None = None,
        workspace_id: str | None = None,
        supabase_access_token: str | None = None,
        # Scope
        projects: list[str] | None = None,
        published_app_urls: list[str] | None = None,
        # Provider configuration
        config_path: str | None = None,
        config_content: dict | None = None,
        fixer_config: dict | None = None,
        mutelist_path: str | None = None,
        mutelist_content: dict | None = None,
    ):
        logger.info("Instantiating Lovable provider...")

        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

        self._session = LovableProvider.setup_session(
            api_token=api_token,
            workspace_id=workspace_id,
        )

        self._identity = LovableProvider.setup_identity(self._session)

        self._fixer_config = fixer_config or {}
        self._supabase_access_token = supabase_access_token or os.environ.get(
            "SUPABASE_ACCESS_TOKEN"
        )
        self._published_app_urls = published_app_urls or []

        if mutelist_content:
            self._mutelist = LovableMutelist(mutelist_content=mutelist_content)
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = LovableMutelist(mutelist_path=mutelist_path)

        self._filter_projects = set(projects) if projects else None

        Provider.set_global_provider(self)

    @property
    def type(self) -> str:
        return self._type

    @property
    def session(self) -> LovableSession:
        return self._session

    @property
    def identity(self) -> LovableIdentityInfo:
        return self._identity

    @property
    def audit_config(self) -> dict:
        return self._audit_config

    @property
    def fixer_config(self) -> dict:
        return self._fixer_config

    @property
    def mutelist(self) -> LovableMutelist:
        return self._mutelist

    @property
    def filter_projects(self) -> set[str] | None:
        return self._filter_projects

    @property
    def published_app_urls(self) -> list[str]:
        return self._published_app_urls

    @property
    def supabase_access_token(self) -> str | None:
        return self._supabase_access_token

    @staticmethod
    def setup_session(
        api_token: str | None = None,
        workspace_id: str | None = None,
    ) -> LovableSession:
        """Build the authenticated Lovable session.

        Credentials may be passed as arguments (API use) or pulled from env vars
        (LOVABLE_API_TOKEN, LOVABLE_WORKSPACE_ID).
        """
        token = api_token or os.environ.get("LOVABLE_API_TOKEN", "")
        workspace = workspace_id or os.environ.get("LOVABLE_WORKSPACE_ID") or None

        if not token:
            raise LovableCredentialsError(
                file=os.path.basename(__file__),
                message=(
                    "Lovable credentials not found. Provide --lovable-api-token "
                    "or set the LOVABLE_API_TOKEN environment variable."
                ),
            )

        try:
            http_session = requests.Session()
            http_session.headers.update(
                {
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "User-Agent": LOVABLE_USER_AGENT,
                }
            )

            return LovableSession(
                api_token=token,
                workspace_id=workspace,
                base_url=f"{LOVABLE_API_BASE_URL}/{LOVABLE_API_VERSION}",
                http_session=http_session,
            )
        except LovableCredentialsError:
            raise
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            raise LovableSessionError(
                file=os.path.basename(__file__), original_exception=error
            )

    @staticmethod
    def setup_identity(session: LovableSession) -> LovableIdentityInfo:
        """Resolve identity by calling /v1/me; degrade to a token-derived
        identity when the endpoint is unreachable."""
        try:
            response = session.http_session.get(
                f"{session.base_url}/me",
                timeout=LOVABLE_DEFAULT_TIMEOUT,
            )

            if response.status_code == 401:
                raise LovableAuthenticationError(
                    file=os.path.basename(__file__),
                    message="Lovable authentication failed. Verify the API token.",
                )

            if response.status_code == 429:
                raise LovableRateLimitError(file=os.path.basename(__file__))

            if response.status_code >= 400:
                # The Cloud API is still evolving; fall back to a token-derived
                # identity so checks targeting the published app still run.
                logger.info(
                    f"Lovable /me returned {response.status_code}; using "
                    "token-derived identity."
                )
                return LovableIdentityInfo(
                    user_id=None,
                    username=f"pat-{session.api_token[:8]}",
                    workspace=(
                        LovableWorkspaceInfo(id=session.workspace_id)
                        if session.workspace_id
                        else None
                    ),
                    workspaces=[],
                )

            data = response.json() or {}
            user = data.get("user") or {}
            workspaces_payload = data.get("workspaces") or []

            workspaces = [
                LovableWorkspaceInfo(
                    id=w.get("id", ""),
                    name=w.get("name", ""),
                    slug=w.get("slug", ""),
                    plan=w.get("plan"),
                )
                for w in workspaces_payload
                if w.get("id")
            ]

            workspace = None
            if session.workspace_id:
                workspace = next(
                    (w for w in workspaces if w.id == session.workspace_id),
                    None,
                )
                if not workspace and workspaces_payload:
                    raise LovableInvalidWorkspaceError(
                        file=os.path.basename(__file__),
                        message=(
                            f"Workspace '{session.workspace_id}' not found or "
                            "not accessible by the provided token."
                        ),
                    )
            elif workspaces:
                workspace = workspaces[0]

            return LovableIdentityInfo(
                user_id=user.get("id"),
                email=user.get("email"),
                username=user.get("username") or user.get("name"),
                workspace=workspace,
                workspaces=workspaces,
            )
        except (
            LovableAuthenticationError,
            LovableRateLimitError,
            LovableInvalidWorkspaceError,
        ):
            raise
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            raise LovableIdentityError(
                file=os.path.basename(__file__), original_exception=error
            )

    @staticmethod
    def validate_credentials(session: LovableSession) -> None:
        """Hit /v1/me to confirm the token is valid."""
        try:
            response = session.http_session.get(
                f"{session.base_url}/me",
                timeout=LOVABLE_DEFAULT_TIMEOUT,
            )

            if response.status_code in (401, 403):
                raise LovableAuthenticationError(
                    file=os.path.basename(__file__),
                    message="Invalid or insufficient Lovable API token.",
                )

            if response.status_code == 429:
                raise LovableRateLimitError(file=os.path.basename(__file__))

            response.raise_for_status()
        except (LovableAuthenticationError, LovableRateLimitError):
            raise
        except requests.exceptions.RequestException as error:
            raise LovableAuthenticationError(
                file=os.path.basename(__file__), original_exception=error
            )

    def print_credentials(self) -> None:
        report_title = (
            f"{Style.BRIGHT}Using the Lovable credentials below:{Style.RESET_ALL}"
        )
        report_lines = [
            f"Authentication: {Fore.YELLOW}API Token{Style.RESET_ALL}",
        ]

        if self.identity.email:
            report_lines.append(
                f"Email: {Fore.YELLOW}{self.identity.email}{Style.RESET_ALL}"
            )
        if self.identity.username:
            report_lines.append(
                f"Username: {Fore.YELLOW}{self.identity.username}{Style.RESET_ALL}"
            )
        if self.identity.workspace:
            ws = self.identity.workspace
            report_lines.append(
                f"Workspace: {Fore.YELLOW}{ws.name or ws.slug or ws.id}"
                f"{Style.RESET_ALL}"
            )
        elif self.identity.workspaces:
            ws_names = ", ".join(
                w.name or w.slug or w.id for w in self.identity.workspaces
            )
            report_lines.append(
                f"Scope: {Fore.YELLOW}{len(self.identity.workspaces)} workspace(s): "
                f"{ws_names}{Style.RESET_ALL}"
            )
        if self.supabase_access_token:
            report_lines.append(
                f"Supabase Backing: {Fore.GREEN}enabled{Style.RESET_ALL}"
            )

        print_boxes(report_lines, report_title)

    @staticmethod
    def test_connection(
        api_token: str | None = None,
        workspace_id: str | None = None,
        raise_on_exception: bool = True,
        provider_id: str | None = None,
    ) -> Connection:
        """Test connection to Lovable Cloud."""
        try:
            session = LovableProvider.setup_session(
                api_token=api_token, workspace_id=workspace_id
            )
            LovableProvider.validate_credentials(session)

            if provider_id:
                identity = LovableProvider.setup_identity(session)
                workspace_ids = {w.id for w in identity.workspaces}
                if identity.workspace and identity.workspace.id:
                    workspace_ids.add(identity.workspace.id)
                if workspace_ids and provider_id not in workspace_ids:
                    raise LovableInvalidProviderIdError(
                        file=os.path.basename(__file__),
                        message=(
                            "The provided credentials do not have access to the "
                            f"Lovable workspace with ID: {provider_id}"
                        ),
                    )

            return Connection(is_connected=True)
        except (
            LovableCredentialsError,
            LovableSessionError,
            LovableAuthenticationError,
            LovableRateLimitError,
            LovableInvalidWorkspaceError,
            LovableInvalidProviderIdError,
        ) as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise error
            return Connection(is_connected=False, error=error)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            formatted_error = LovableAuthenticationError(
                file=os.path.basename(__file__), original_exception=error
            )
            if raise_on_exception:
                raise formatted_error
            return Connection(is_connected=False, error=formatted_error)

    def validate_arguments(self) -> None:
        return None
