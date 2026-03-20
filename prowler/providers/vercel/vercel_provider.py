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
from prowler.providers.vercel.exceptions.exceptions import (
    VercelAuthenticationError,
    VercelCredentialsError,
    VercelIdentityError,
    VercelInvalidTeamError,
    VercelRateLimitError,
    VercelSessionError,
)
from prowler.providers.vercel.lib.mutelist.mutelist import VercelMutelist
from prowler.providers.vercel.models import (
    VercelIdentityInfo,
    VercelSession,
    VercelTeamInfo,
)


class VercelProvider(Provider):
    """Vercel provider."""

    _type: str = "vercel"
    _session: VercelSession
    _identity: VercelIdentityInfo
    _audit_config: dict
    _fixer_config: dict
    _mutelist: VercelMutelist
    _filter_projects: set[str] | None
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        # Authentication credentials
        api_token: str = None,
        team_id: str = None,
        # Scope
        projects: list[str] | None = None,
        # Provider configuration
        config_path: str = None,
        config_content: dict | None = None,
        fixer_config: dict = {},
        mutelist_path: str = None,
        mutelist_content: dict = None,
    ):
        logger.info("Instantiating Vercel provider...")

        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

        self._session = VercelProvider.setup_session(
            api_token=api_token,
            team_id=team_id,
        )

        self._identity = VercelProvider.setup_identity(self._session)

        self._fixer_config = fixer_config

        if mutelist_content:
            self._mutelist = VercelMutelist(mutelist_content=mutelist_content)
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = VercelMutelist(mutelist_path=mutelist_path)

        # Store project filter for filtering resources across services
        self._filter_projects = set(projects) if projects else None

        Provider.set_global_provider(self)

    @property
    def type(self):
        return self._type

    @property
    def session(self):
        return self._session

    @property
    def identity(self):
        return self._identity

    @property
    def audit_config(self):
        return self._audit_config

    @property
    def fixer_config(self):
        return self._fixer_config

    @property
    def mutelist(self) -> VercelMutelist:
        return self._mutelist

    @property
    def filter_projects(self) -> set[str] | None:
        """Project filter from --project argument to filter scanned projects."""
        return self._filter_projects

    @staticmethod
    def setup_session(
        api_token: str = None,
        team_id: str = None,
    ) -> VercelSession:
        """Initialize Vercel API session.

        Credentials can be provided as arguments (for API use) or read from
        environment variables:
        - VERCEL_TOKEN (API Bearer Token)
        - VERCEL_TEAM (Team ID or slug, optional)

        Args:
            api_token: Vercel API token (optional, falls back to VERCEL_TOKEN env var).
            team_id: Vercel team ID or slug (optional, falls back to VERCEL_TEAM env var).

        Returns:
            VercelSession: The initialized Vercel session.

        Raises:
            VercelCredentialsError: If no credentials are provided.
            VercelSessionError: If session setup fails.
        """
        token = api_token or os.environ.get("VERCEL_TOKEN", "")
        team = team_id or os.environ.get("VERCEL_TEAM", "") or None

        if not token:
            raise VercelCredentialsError(
                file=os.path.basename(__file__),
                message="Vercel credentials not found. Provide an api_token or set the VERCEL_TOKEN environment variable.",
            )

        try:
            http_session = requests.Session()
            http_session.headers.update(
                {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                }
            )

            return VercelSession(
                token=token,
                team_id=team,
                http_session=http_session,
            )
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            raise VercelSessionError(
                file=os.path.basename(__file__),
                original_exception=error,
            )

    @staticmethod
    def setup_identity(session: VercelSession) -> VercelIdentityInfo:
        """Fetch user and team metadata for Vercel.

        Args:
            session: The Vercel session.

        Returns:
            VercelIdentityInfo: The identity information.

        Raises:
            VercelIdentityError: If identity setup fails.
        """
        try:
            http = session.http_session
            params = {"teamId": session.team_id} if session.team_id else {}

            # Get user info
            response = http.get(
                f"{session.base_url}/v2/user", params=params, timeout=30
            )
            response.raise_for_status()
            user_data = response.json().get("user", {})

            user_id = user_data.get("id")
            username = user_data.get("username")
            email = user_data.get("email")

            # Get team info
            team_info = None
            all_teams = []

            if session.team_id:
                # Specific team requested — fetch just that one
                params = {"teamId": session.team_id}
                team_response = http.get(
                    f"{session.base_url}/v2/teams/{session.team_id}",
                    params=params,
                    timeout=30,
                )
                if team_response.status_code == 200:
                    team_data = team_response.json()
                    team_info = VercelTeamInfo(
                        id=team_data.get("id", session.team_id),
                        name=team_data.get("name", ""),
                        slug=team_data.get("slug", ""),
                    )
                    all_teams = [team_info]
                elif team_response.status_code in (404, 403):
                    raise VercelInvalidTeamError(
                        file=os.path.basename(__file__),
                        message=f"Team '{session.team_id}' not found or not accessible.",
                    )
                else:
                    team_response.raise_for_status()
            else:
                # No team specified — auto-discover all teams the user belongs to
                try:
                    teams_response = http.get(
                        f"{session.base_url}/v2/teams",
                        params={"limit": 100},
                        timeout=30,
                    )
                    if teams_response.status_code == 200:
                        teams_data = teams_response.json().get("teams", [])
                        for t in teams_data:
                            all_teams.append(
                                VercelTeamInfo(
                                    id=t.get("id", ""),
                                    name=t.get("name", ""),
                                    slug=t.get("slug", ""),
                                )
                            )
                        if all_teams:
                            logger.info(
                                f"Auto-discovered {len(all_teams)} team(s): "
                                f"{', '.join(t.name for t in all_teams)}"
                            )
                except Exception as teams_error:
                    logger.warning(f"Could not auto-discover teams: {teams_error}")

            return VercelIdentityInfo(
                user_id=user_id,
                username=username,
                email=email,
                team=team_info,
                teams=all_teams,
            )
        except VercelInvalidTeamError:
            raise
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            raise VercelIdentityError(
                file=os.path.basename(__file__),
                original_exception=error,
            )

    @staticmethod
    def validate_credentials(session: VercelSession) -> None:
        """Validate Vercel credentials by calling GET /v2/user.

        Args:
            session: The Vercel session to validate.

        Raises:
            VercelAuthenticationError: If authentication fails.
            VercelRateLimitError: If rate limited.
        """
        try:
            params = {}
            if session.team_id:
                params["teamId"] = session.team_id
            response = session.http_session.get(
                f"{session.base_url}/v2/user", params=params, timeout=30
            )

            if response.status_code == 401:
                raise VercelAuthenticationError(
                    file=os.path.basename(__file__),
                    message="Invalid or expired Vercel API token.",
                )

            if response.status_code == 403:
                raise VercelAuthenticationError(
                    file=os.path.basename(__file__),
                    message="Insufficient permissions for the Vercel API token.",
                )

            if response.status_code == 429:
                raise VercelRateLimitError(
                    file=os.path.basename(__file__),
                )

            response.raise_for_status()

        except (VercelAuthenticationError, VercelRateLimitError):
            raise
        except requests.exceptions.RequestException as error:
            raise VercelAuthenticationError(
                file=os.path.basename(__file__),
                original_exception=error,
            )

    def print_credentials(self) -> None:
        report_title = (
            f"{Style.BRIGHT}Using the Vercel credentials below:{Style.RESET_ALL}"
        )
        report_lines = []

        report_lines.append(f"Authentication: {Fore.YELLOW}API Token{Style.RESET_ALL}")

        if self.identity.email:
            report_lines.append(
                f"Email: {Fore.YELLOW}{self.identity.email}{Style.RESET_ALL}"
            )

        if self.identity.username:
            report_lines.append(
                f"Username: {Fore.YELLOW}{self.identity.username}{Style.RESET_ALL}"
            )

        if self.identity.team:
            report_lines.append(
                f"Team: {Fore.YELLOW}{self.identity.team.name} ({self.identity.team.slug}){Style.RESET_ALL}"
            )
        elif self.identity.teams:
            team_names = ", ".join(f"{t.name} ({t.slug})" for t in self.identity.teams)
            report_lines.append(
                f"Scope: {Fore.YELLOW}Personal Account + {len(self.identity.teams)} team(s): {team_names}{Style.RESET_ALL}"
            )
        else:
            report_lines.append(
                f"Scope: {Fore.YELLOW}Personal Account{Style.RESET_ALL}"
            )

        print_boxes(report_lines, report_title)

    @staticmethod
    def test_connection(
        api_token: str = None,
        team_id: str = None,
        raise_on_exception: bool = True,
        provider_id: str = None,
    ) -> Connection:
        """Test connection to Vercel.

        Credentials can be provided as arguments (for API use) or read from
        environment variables (VERCEL_TOKEN, VERCEL_TEAM).

        Args:
            api_token: Vercel API token (optional, falls back to env var).
            team_id: Vercel team ID or slug (optional, falls back to env var).
            raise_on_exception: Whether to raise or return errors.
            provider_id: The provider ID.

        Returns:
            Connection: Connection object with is_connected status.
        """
        try:
            session = VercelProvider.setup_session(
                api_token=api_token,
                team_id=team_id,
            )
            VercelProvider.validate_credentials(session)
            return Connection(is_connected=True)

        except (
            VercelCredentialsError,
            VercelSessionError,
            VercelAuthenticationError,
            VercelRateLimitError,
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
            formatted_error = VercelAuthenticationError(
                file=os.path.basename(__file__),
                original_exception=error,
            )
            if raise_on_exception:
                raise formatted_error
            return Connection(is_connected=False, error=formatted_error)

    def validate_arguments(self) -> None:
        return None
