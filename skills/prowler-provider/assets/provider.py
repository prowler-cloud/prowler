# Example: Provider Class Template (GitHub Provider)
# Source: prowler/providers/github/github_provider.py


from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.mutelist.mutelist import Mutelist
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider


class GithubProvider(Provider):
    """
    GitHub Provider - Template for creating new providers.

    Required attributes (from abstract Provider):
    - _type: str - Provider identifier
    - _session: Session model - Authentication credentials
    - _identity: Identity model - Authenticated user info
    - _audit_config: dict - Check configuration
    - _mutelist: Mutelist - Finding filtering
    """

    _type: str = "github"
    _auth_method: str = None
    _session: "GithubSession"
    _identity: "GithubIdentityInfo"
    _audit_config: dict
    _mutelist: Mutelist
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        # Authentication credentials
        personal_access_token: str = "",
        # Provider configuration
        config_path: str = None,
        config_content: dict = None,
        fixer_config: dict = {},
        mutelist_path: str = None,
        mutelist_content: dict = None,
        # Provider scoping
        repositories: list = None,
        organizations: list = None,
    ):
        logger.info("Instantiating GitHub Provider...")

        # Store scoping configuration
        self._repositories = repositories or []
        self._organizations = organizations or []

        # Step 1: Setup session (authentication)
        self._session = self.setup_session(personal_access_token)
        self._auth_method = "Personal Access Token"

        # Step 2: Setup identity (who is authenticated)
        self._identity = self.setup_identity(self._session)

        # Step 3: Load audit config
        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

        # Step 4: Load fixer config
        self._fixer_config = fixer_config

        # Step 5: Load mutelist
        if mutelist_content:
            self._mutelist = GithubMutelist(mutelist_content=mutelist_content)
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = GithubMutelist(mutelist_path=mutelist_path)

        # CRITICAL: Register as global provider
        Provider.set_global_provider(self)

    # Required property implementations
    @property
    def type(self) -> str:
        return self._type

    @property
    def session(self) -> "GithubSession":
        return self._session

    @property
    def identity(self) -> "GithubIdentityInfo":
        return self._identity

    @property
    def audit_config(self) -> dict:
        return self._audit_config

    @property
    def mutelist(self) -> Mutelist:
        return self._mutelist

    @staticmethod
    def setup_session(personal_access_token: str) -> "GithubSession":
        """Create authenticated session from credentials."""
        if not personal_access_token:
            raise ValueError("Personal access token required")
        return GithubSession(token=personal_access_token)

    @staticmethod
    def setup_identity(session: "GithubSession") -> "GithubIdentityInfo":
        """Get identity info for authenticated user."""
        # Make API call to get user info
        # g = Github(auth=Auth.Token(session.token))
        # user = g.get_user()
        return GithubIdentityInfo(
            account_id="user-id",
            account_name="username",
            account_url="https://github.com/username",
        )

    def print_credentials(self):
        """Display credentials in CLI output."""
        print(f"GitHub Account: {self.identity.account_name}")
        print(f"Auth Method: {self._auth_method}")

    @staticmethod
    def test_connection(
        personal_access_token: str = None,
        raise_on_exception: bool = True,
    ) -> Connection:
        """Test if credentials can connect to the provider."""
        try:
            session = GithubProvider.setup_session(personal_access_token)
            GithubProvider.setup_identity(session)
            return Connection(is_connected=True)
        except Exception as e:
            if raise_on_exception:
                raise
            return Connection(is_connected=False, error=str(e))
