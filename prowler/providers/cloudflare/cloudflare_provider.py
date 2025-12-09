from __future__ import annotations

import os
from typing import TYPE_CHECKING, Iterable

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
    CloudflareAPIError,
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

if TYPE_CHECKING:
    from prowler.providers.cloudflare.services.zones.zones_service import CloudflareZone


class CloudflareProvider(Provider):
    """Cloudflare provider."""

    _type: str = "cloudflare"
    _session: CloudflareSession
    _identity: CloudflareIdentityInfo
    _audit_config: dict
    _fixer_config: dict
    _mutelist: CloudflareMutelist
    _zones: list[CloudflareZone]
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        api_token: str = None,
        api_key: str = None,
        api_email: str = None,
        account_ids: Iterable[str] | None = None,
        zones: Iterable[str] | None = None,
        config_path: str = None,
        config_content: dict | None = None,
        fixer_config: dict = {},
        mutelist_path: str = None,
        mutelist_content: dict = None,
    ):
        logger.info("Instantiating Cloudflare provider...")

        self._session = CloudflareProvider.setup_session(
            api_token=api_token,
            api_key=api_key,
            api_email=api_email,
        )

        self._identity = CloudflareProvider.setup_identity(
            self._session, account_ids=account_ids
        )

        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

        self._fixer_config = fixer_config

        if mutelist_content:
            self._mutelist = CloudflareMutelist(mutelist_content=mutelist_content)
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = CloudflareMutelist(mutelist_path=mutelist_path)

        self._zones = self._discover_zones(zones)
        self._identity.audited_zones = [zone.id for zone in self._zones]

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
    def zones(self) -> list[CloudflareZone]:
        return self._zones

    @property
    def accounts(self) -> list[CloudflareAccount]:
        return self._identity.accounts

    @staticmethod
    def setup_session(
        api_token: str = None,
        api_key: str = None,
        api_email: str = None,
    ) -> CloudflareSession:
        """Initialize Cloudflare SDK client."""
        token = api_token or os.environ.get("CLOUDFLARE_API_TOKEN", "")
        key = api_key or os.environ.get("CLOUDFLARE_API_KEY", "")
        email = api_email or os.environ.get("CLOUDFLARE_API_EMAIL", "")

        if not token and not (key and email):
            raise CloudflareCredentialsError(
                file=os.path.basename(__file__),
                message="Cloudflare credentials not found. Provide --cloudflare-api-token or --cloudflare-api-key and --cloudflare-api-email.",
            )

        try:
            if token:
                client = Cloudflare(api_token=token)
            else:
                client = Cloudflare(api_email=email, api_key=key)

            return CloudflareSession(
                client=client,
                api_token=token or None,
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

    @staticmethod
    def setup_identity(
        session: CloudflareSession, account_ids: Iterable[str] | None = None
    ) -> CloudflareIdentityInfo:
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
            provided_accounts = set(account_ids) if account_ids else set()
            seen_account_ids: set[str] = set()

            for account in client.accounts.list():
                account_id = getattr(account, "id", None)
                # Prevent infinite loop - skip if we've seen this account
                if account_id in seen_account_ids:
                    break
                seen_account_ids.add(account_id)

                account_name = getattr(account, "name", None)
                account_type = getattr(account, "type", None)
                if provided_accounts and account_id not in provided_accounts:
                    continue
                accounts.append(
                    CloudflareAccount(
                        id=account_id,
                        name=account_name,
                        type=account_type,
                    )
                )

            if provided_accounts and not accounts:
                raise CloudflareInvalidAccountError(
                    message="None of the supplied Cloudflare accounts are accessible with the provided credentials."
                )

            audited_accounts = (
                [account.id for account in accounts]
                if accounts
                else list(provided_accounts)
            )

            return CloudflareIdentityInfo(
                user_id=user_id,
                email=email,
                accounts=accounts,
                audited_accounts=audited_accounts,
            )
        except CloudflareInvalidAccountError:
            raise
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            raise CloudflareIdentityError(
                file=os.path.basename(__file__),
                original_exception=error,
            )

    def _discover_zones(
        self, provided_zones: Iterable[str] | None = None
    ) -> list[CloudflareZone]:
        """Enumerate Cloudflare zones available to the authenticated identity."""
        # Late import to avoid circular dependency
        from prowler.providers.cloudflare.services.zones.zones_service import (
            CloudflareZone,
        )

        zones: list[CloudflareZone] = []
        filters = set(provided_zones) if provided_zones else set()
        seen_zone_ids: set[str] = set()
        try:
            for zone in self._session.client.zones.list():
                zone_id = getattr(zone, "id", None)
                # Prevent infinite loop - skip if we've seen this zone
                if zone_id in seen_zone_ids:
                    break
                seen_zone_ids.add(zone_id)

                zone_account = getattr(zone, "account", None)
                account_id = getattr(zone_account, "id", None) if zone_account else None
                if (
                    self._identity.audited_accounts
                    and account_id not in self._identity.audited_accounts
                ):
                    continue
                zone_name = getattr(zone, "name", None)
                if filters and zone_id not in filters and zone_name not in filters:
                    continue
                zone_plan = getattr(zone, "plan", None)
                zones.append(
                    CloudflareZone(
                        id=zone_id,
                        name=zone_name,
                        status=getattr(zone, "status", None),
                        paused=getattr(zone, "paused", False),
                        account=(
                            CloudflareAccount(
                                id=account_id,
                                name=(
                                    getattr(zone_account, "name", "")
                                    if zone_account
                                    else ""
                                ),
                                type=(
                                    getattr(zone_account, "type", None)
                                    if zone_account
                                    else None
                                ),
                            )
                            if zone_account
                            else None
                        ),
                        plan=getattr(zone_plan, "name", None) if zone_plan else None,
                    )
                )

            if not zones:
                logger.warning(
                    "No Cloudflare zones discovered with current credentials and filters."
                )
            return zones
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            raise CloudflareAPIError(
                file=os.path.basename(__file__),
                original_exception=error,
                message="Failed to enumerate Cloudflare zones.",
            )

    def print_credentials(self) -> None:
        accounts = (
            ", ".join([account.id for account in self.accounts])
            if self.accounts
            else "all accessible accounts"
        )
        zones = (
            ", ".join([zone.name for zone in self._zones])
            if self._zones
            else "all accessible zones"
        )
        report_title = (
            f"{Style.BRIGHT}Using the Cloudflare credentials below:{Style.RESET_ALL}"
        )
        report_lines = [
            f"Account: {Fore.YELLOW}{accounts}{Style.RESET_ALL}",
            f"Zones: {Fore.YELLOW}{zones}{Style.RESET_ALL}",
        ]
        if self.identity.email:
            report_lines.append(
                f"Email: {Fore.YELLOW}{self.identity.email}{Style.RESET_ALL}"
            )

        print_boxes(report_lines, report_title)

    def test_connection(self) -> Connection:
        try:
            _ = self._session.client.user.get()
            return Connection(is_connected=True)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return Connection(is_connected=False, error=error)

    def validate_arguments(self) -> None:
        return None
