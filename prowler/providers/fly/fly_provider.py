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
from prowler.providers.fly.exceptions.exceptions import (
    FlyAuthenticationError,
    FlyCredentialsError,
    FlyIdentityError,
    FlyInvalidOrganizationError,
    FlyRateLimitError,
    FlySessionError,
)
from prowler.providers.fly.lib.mutelist.mutelist import FlyMutelist
from prowler.providers.fly.models import (
    FlyIdentityInfo,
    FlyOrganization,
    FlySession,
)

ORGANIZATIONS_QUERY = """
query {
  organizations {
    nodes {
      id
      slug
      name
    }
  }
}
"""


class FlyProvider(Provider):
    """Fly.io provider.

    Audits Fly.io organizations through the Machines API (apps, machines,
    volumes, secret metadata) and the Fly.io GraphQL API (organizations and
    allocated public IP addresses). Only read operations are performed, so an
    organization-scoped read-only token is enough to run every check.
    """

    _type: str = "fly"
    sdk_only: bool = True
    _session: FlySession
    _identity: FlyIdentityInfo
    _audit_config: dict
    _fixer_config: dict
    _mutelist: FlyMutelist
    _filter_apps: set[str] | None
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        # Authentication credentials
        api_token: str = None,
        organization: str = None,
        # Scope
        apps: list[str] | None = None,
        # Provider configuration
        config_path: str = None,
        config_content: dict | None = None,
        fixer_config: dict = {},
        mutelist_path: str = None,
        mutelist_content: dict = None,
    ):
        logger.info("Instantiating Fly provider...")

        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

        self._session = FlyProvider.setup_session(
            api_token=api_token,
            organization=organization,
        )

        self._identity = FlyProvider.setup_identity(self._session)

        self._fixer_config = fixer_config

        if mutelist_content:
            self._mutelist = FlyMutelist(mutelist_content=mutelist_content)
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = FlyMutelist(mutelist_path=mutelist_path)

        self._filter_apps = set(apps) if apps else None

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
    def mutelist(self) -> FlyMutelist:
        return self._mutelist

    @property
    def filter_apps(self) -> set[str] | None:
        """App filter from the --app argument used to narrow the scan."""
        return self._filter_apps

    @staticmethod
    def setup_session(
        api_token: str = None,
        organization: str = None,
    ) -> FlySession:
        """Initialize the Fly.io API session.

        Credentials can be provided as arguments (for API use) or read from
        environment variables:
        - FLY_API_TOKEN (Fly.io API token, org-scoped read-only is enough)
        - FLY_ORG (organization slug, optional)

        Args:
            api_token: Fly.io API token (falls back to the FLY_API_TOKEN env var).
            organization: Organization slug (falls back to the FLY_ORG env var).

        Returns:
            FlySession: The initialized Fly.io session.

        Raises:
            FlyCredentialsError: If no token is available.
            FlySessionError: If session setup fails.
        """
        token = api_token or os.environ.get("FLY_API_TOKEN", "")
        org = organization or os.environ.get("FLY_ORG", "") or None

        if not token:
            raise FlyCredentialsError(
                file=os.path.basename(__file__),
                message="Fly.io credentials not found. Provide an api_token or set the FLY_API_TOKEN environment variable.",
            )

        try:
            http_session = requests.Session()
            http_session.headers.update(
                {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                }
            )

            return FlySession(
                token=token,
                org_slug=org,
                http_session=http_session,
            )
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            raise FlySessionError(
                file=os.path.basename(__file__),
                original_exception=error,
            )

    @staticmethod
    def setup_identity(session: FlySession) -> FlyIdentityInfo:
        """Fetch the organizations the token can read.

        Args:
            session: The Fly.io session.

        Returns:
            FlyIdentityInfo: The identity information.

        Raises:
            FlyInvalidOrganizationError: If the requested organization is not readable.
            FlyIdentityError: If identity setup fails.
        """
        try:
            organizations = FlyProvider._get_organizations(session)

            if session.org_slug:
                for org in organizations:
                    if session.org_slug in (org.slug, org.id):
                        return FlyIdentityInfo(
                            organization=org, organizations=organizations
                        )
                raise FlyInvalidOrganizationError(
                    file=os.path.basename(__file__),
                    message=f"Organization '{session.org_slug}' not found or not accessible with this token.",
                )

            if len(organizations) == 1:
                # An org-scoped token only ever resolves to its own organization
                return FlyIdentityInfo(
                    organization=organizations[0], organizations=organizations
                )

            logger.info(
                f"Auto-discovered {len(organizations)} organization(s): "
                f"{', '.join(org.slug for org in organizations)}"
            )
            return FlyIdentityInfo(organizations=organizations)
        except FlyInvalidOrganizationError:
            raise
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            raise FlyIdentityError(
                file=os.path.basename(__file__),
                original_exception=error,
            )

    @staticmethod
    def _get_organizations(session: FlySession) -> list[FlyOrganization]:
        """Read every organization the token is allowed to see."""
        response = session.http_session.post(
            session.graphql_url,
            json={"query": ORGANIZATIONS_QUERY},
            timeout=30,
        )
        response.raise_for_status()
        payload = response.json()

        if payload.get("errors"):
            raise FlyIdentityError(
                file=os.path.basename(__file__),
                message=f"Fly.io GraphQL error while listing organizations: {payload['errors']}",
            )

        nodes = payload.get("data", {}).get("organizations", {}).get("nodes", []) or []
        return [
            FlyOrganization(
                id=node.get("id", ""),
                slug=node.get("slug", ""),
                name=node.get("name", "") or node.get("slug", ""),
            )
            for node in nodes
            if node.get("slug")
        ]

    @staticmethod
    def validate_credentials(session: FlySession) -> None:
        """Validate Fly.io credentials against the Machines API.

        Args:
            session: The Fly.io session to validate.

        Raises:
            FlyAuthenticationError: If authentication fails.
            FlyRateLimitError: If rate limited.
        """
        try:
            params = {"org_slug": session.org_slug} if session.org_slug else {}
            response = session.http_session.get(
                f"{session.machines_base_url}/apps", params=params, timeout=30
            )

            if response.status_code in (401, 403):
                raise FlyAuthenticationError(
                    file=os.path.basename(__file__),
                    message="Invalid, expired or insufficiently scoped Fly.io token.",
                )

            if response.status_code == 429:
                raise FlyRateLimitError(file=os.path.basename(__file__))

            response.raise_for_status()

        except (FlyAuthenticationError, FlyRateLimitError):
            raise
        except requests.exceptions.RequestException as error:
            raise FlyAuthenticationError(
                file=os.path.basename(__file__),
                original_exception=error,
            )

    def print_credentials(self) -> None:
        report_title = (
            f"{Style.BRIGHT}Using the Fly.io credentials below:{Style.RESET_ALL}"
        )
        report_lines = [f"Authentication: {Fore.YELLOW}API Token{Style.RESET_ALL}"]

        if self.identity.organization:
            report_lines.append(
                f"Organization: {Fore.YELLOW}{self.identity.organization.name} "
                f"({self.identity.organization.slug}){Style.RESET_ALL}"
            )
        else:
            org_slugs = ", ".join(org.slug for org in self.identity.organizations)
            report_lines.append(
                f"Organizations: {Fore.YELLOW}{org_slugs or 'none'}{Style.RESET_ALL}"
            )

        if self.filter_apps:
            report_lines.append(
                f"Apps: {Fore.YELLOW}{', '.join(sorted(self.filter_apps))}{Style.RESET_ALL}"
            )

        print_boxes(report_lines, report_title)

    @staticmethod
    def test_connection(
        api_token: str = None,
        organization: str = None,
        raise_on_exception: bool = True,
        provider_id: str = None,
    ) -> Connection:
        """Test the connection to Fly.io.

        Args:
            api_token: Fly.io API token (falls back to the FLY_API_TOKEN env var).
            organization: Organization slug (falls back to the FLY_ORG env var).
            raise_on_exception: Whether to raise or return errors.
            provider_id: The provider ID, used as the organization slug when
                ``organization`` is not given.

        Returns:
            Connection: Connection object with is_connected status.
        """
        try:
            session = FlyProvider.setup_session(
                api_token=api_token,
                organization=organization or provider_id,
            )
            FlyProvider.validate_credentials(session)
            return Connection(is_connected=True)

        except (
            FlyCredentialsError,
            FlySessionError,
            FlyAuthenticationError,
            FlyRateLimitError,
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
            formatted_error = FlyAuthenticationError(
                file=os.path.basename(__file__),
                original_exception=error,
            )
            if raise_on_exception:
                raise formatted_error
            return Connection(is_connected=False, error=formatted_error)

    def validate_arguments(self) -> None:
        return None
