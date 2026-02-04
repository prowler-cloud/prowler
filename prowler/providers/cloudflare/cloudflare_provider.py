import os
from typing import Iterable

from cloudflare import Cloudflare
from colorama import Fore, Style

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.cloudflare.exceptions.exceptions import (
    CloudflareCredentialsError,
    CloudflareIdentityError,
    CloudflareInvalidAccountError,
    CloudflareSessionError,
)
from prowler.providers.cloudflare.lib.mutelist.mutelist import CloudflareMutelist
from prowler.providers.cloudflare.models import (
    CloudflareAccount,
    CloudflareIdentityInfo,
    CloudflareSession,
)
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider


class CloudflareProvider(Provider):
    """Cloudflare provider."""

    _type: str = "cloudflare"
    _session: CloudflareSession
    _identity: CloudflareIdentityInfo
    _audit_config: dict
    _fixer_config: dict
    _mutelist: CloudflareMutelist
    _filter_zones: set[str] | None
    _filter_accounts: set[str] | None
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        filter_zones: Iterable[str] | None = None,
        filter_accounts: Iterable[str] | None = None,
        config_path: str = None,
        config_content: dict | None = None,
        fixer_config: dict = {},
        mutelist_path: str = None,
        mutelist_content: dict = None,
        api_token: str = None,
        api_key: str = None,
        api_email: str = None,
    ):
        logger.info("Instantiating Cloudflare provider...")

        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

        max_retries = self._audit_config.get("max_retries", 2)

        self._session = CloudflareProvider.setup_session(
            max_retries=max_retries,
            api_token=api_token,
            api_key=api_key,
            api_email=api_email,
        )

        self._identity = CloudflareProvider.setup_identity(self._session)

        self._fixer_config = fixer_config

        if mutelist_content:
            self._mutelist = CloudflareMutelist(mutelist_content=mutelist_content)
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = CloudflareMutelist(mutelist_path=mutelist_path)

        # Store zone filter for filtering resources across services
        self._filter_zones = set(filter_zones) if filter_zones else None

        # Store account filter and restrict audited_accounts accordingly
        self._filter_accounts = set(filter_accounts) if filter_accounts else None
        if self._filter_accounts:
            discovered_account_ids = {account.id for account in self._identity.accounts}
            invalid_accounts = self._filter_accounts - discovered_account_ids
            if invalid_accounts:
                invalid_str = ", ".join(sorted(invalid_accounts))
                raise CloudflareInvalidAccountError(
                    file=os.path.basename(__file__),
                    message=f"Account IDs not found: {invalid_str}.",
                )
            self._identity.audited_accounts = [
                account_id
                for account_id in self._identity.audited_accounts
                if account_id in self._filter_accounts
            ]

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
    def mutelist(self) -> CloudflareMutelist:
        return self._mutelist

    @property
    def filter_zones(self) -> set[str] | None:
        """Zone filter from --region argument to filter resources."""
        return self._filter_zones

    @property
    def filter_accounts(self) -> set[str] | None:
        """Account filter from --account-id argument to restrict scanned accounts."""
        return self._filter_accounts

    @property
    def accounts(self) -> list[CloudflareAccount]:
        return self._identity.accounts

    @staticmethod
    def setup_session(
        max_retries: int = 2,
        api_token: str = None,
        api_key: str = None,
        api_email: str = None,
    ) -> CloudflareSession:
        """Initialize Cloudflare SDK client.

        Credentials can be provided as arguments or read from environment variables:
        - CLOUDFLARE_API_TOKEN (recommended)
        - CLOUDFLARE_API_KEY and CLOUDFLARE_API_EMAIL (legacy)

        Args:
            max_retries: Maximum number of retries for API requests (default is 2).
            api_token: Cloudflare API token (optional, falls back to env var).
            api_key: Cloudflare API key (optional, falls back to env var).
            api_email: Cloudflare API email (optional, falls back to env var).
        """
        # Use provided credentials or fall back to environment variables
        token = api_token or os.environ.get("CLOUDFLARE_API_TOKEN", "")
        key = api_key or os.environ.get("CLOUDFLARE_API_KEY", "")
        email = api_email or os.environ.get("CLOUDFLARE_API_EMAIL", "")

        # Warn if both auth methods are set, use API Token (recommended)
        if token and key and email:
            logger.error(
                "Both API Token and API Key + Email credentials are set. "
                "Using API Token (recommended). "
                "To avoid this error, unset CLOUDFLARE_API_KEY and CLOUDFLARE_API_EMAIL, or CLOUDFLARE_API_TOKEN."
            )

        # The Cloudflare SDK reads credentials from environment variables automatically.
        # To ensure we use only the selected auth method, temporarily unset env vars.
        env_token = os.environ.pop("CLOUDFLARE_API_TOKEN", None)
        env_key = os.environ.pop("CLOUDFLARE_API_KEY", None)
        env_email = os.environ.pop("CLOUDFLARE_API_EMAIL", None)

        try:
            if token:
                client = Cloudflare(api_token=token, max_retries=max_retries)
            elif key and email:
                client = Cloudflare(
                    api_key=key, api_email=email, max_retries=max_retries
                )
            else:
                raise CloudflareCredentialsError(
                    file=os.path.basename(__file__),
                    message="Cloudflare credentials not found. Set CLOUDFLARE_API_TOKEN or both CLOUDFLARE_API_KEY and CLOUDFLARE_API_EMAIL environment variables.",
                )

            return CloudflareSession(
                client=client,
                api_token=client.api_token,
                api_key=key or None,
                api_email=email or None,
            )
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            raise CloudflareSessionError(
                file=os.path.basename(__file__),
                original_exception=error,
            )
        finally:
            # Restore environment variables
            if env_token:
                os.environ["CLOUDFLARE_API_TOKEN"] = env_token
            if env_key:
                os.environ["CLOUDFLARE_API_KEY"] = env_key
            if env_email:
                os.environ["CLOUDFLARE_API_EMAIL"] = env_email

    @staticmethod
    def setup_identity(session: CloudflareSession) -> CloudflareIdentityInfo:
        """Fetch user and account metadata for Cloudflare."""
        try:
            client = session.client
            user_id = None
            email = None
            try:
                user_info = client.user.get()
                user_id = getattr(user_info, "id", None)
                email = getattr(user_info, "email", None)
            except Exception as error:
                logger.warning(
                    f"Unable to retrieve Cloudflare user info: {error}. Continuing with limited identity details."
                )

            accounts: list[CloudflareAccount] = []
            seen_account_ids: set[str] = set()

            for account in client.accounts.list():
                account_id = getattr(account, "id", None)
                # Prevent infinite loop - skip if we've seen this account
                if account_id in seen_account_ids:
                    break
                seen_account_ids.add(account_id)

                account_name = getattr(account, "name", None)
                account_type = getattr(account, "type", None)
                accounts.append(
                    CloudflareAccount(
                        id=account_id,
                        name=account_name,
                        type=account_type,
                    )
                )

            audited_accounts = [account.id for account in accounts]

            return CloudflareIdentityInfo(
                user_id=user_id,
                email=email,
                accounts=accounts,
                audited_accounts=audited_accounts,
            )
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            raise CloudflareIdentityError(
                file=os.path.basename(__file__),
                original_exception=error,
            )

    def print_credentials(self) -> None:
        report_title = (
            f"{Style.BRIGHT}Using the Cloudflare credentials below:{Style.RESET_ALL}"
        )
        report_lines = []

        # Authentication method
        if self._session.api_token:
            report_lines.append(
                f"Authentication: {Fore.YELLOW}API Token{Style.RESET_ALL}"
            )
        elif self._session.api_key and self._session.api_email:
            report_lines.append(
                f"Authentication: {Fore.YELLOW}API Key + Email{Style.RESET_ALL}"
            )

        # Email (from identity or session)
        email = self.identity.email or self._session.api_email
        if email:
            report_lines.append(f"Email: {Fore.YELLOW}{email}{Style.RESET_ALL}")

        # Audited accounts (only the ones that will actually be scanned)
        audited_accounts = self.identity.audited_accounts
        if audited_accounts:
            account_names = {
                account.id: account.name for account in self.identity.accounts
            }
            accounts_str = ", ".join(
                (
                    f"{account_id} ({account_names[account_id]})"
                    if account_id in account_names and account_names[account_id]
                    else account_id
                )
                for account_id in audited_accounts
            )
            report_lines.append(
                f"Audited Accounts: {Fore.YELLOW}{accounts_str}{Style.RESET_ALL}"
            )

        print_boxes(report_lines, report_title)

    @staticmethod
    def test_connection(
        api_token: str = None,
        api_key: str = None,
        api_email: str = None,
        raise_on_exception: bool = True,
        provider_id: str = None,
    ) -> Connection:
        """Test connection to Cloudflare.

        Test the connection to Cloudflare using the provided credentials.

        Args:
            api_token: Cloudflare API token (optional, falls back to env var).
            api_key: Cloudflare API key (optional, falls back to env var).
            api_email: Cloudflare API email (optional, falls back to env var).
            raise_on_exception: Flag indicating whether to raise an exception if the connection fails.
            provider_id: The provider ID (Cloudflare account ID).

        Returns:
            Connection: Connection object with is_connected status.
        """
        try:
            session = CloudflareProvider.setup_session(
                api_token=api_token,
                api_key=api_key,
                api_email=api_email,
            )
            _ = session.client.user.get()
            return Connection(is_connected=True)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise error
            return Connection(is_connected=False, error=error)

    def validate_arguments(self) -> None:
        return None
