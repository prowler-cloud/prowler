from datetime import datetime
from typing import Any, ClassVar, Optional

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.cloudflare.lib.service.scope import collect_pages
from prowler.providers.cloudflare.lib.service.service import CloudflareService

SUPER_ADMIN_ROLE_NAME = "Super Administrator - All Privileges"

ACCOUNT_RESOURCE_PREFIX = "com.cloudflare.api.account."
ZONE_RESOURCE_PREFIX = "com.cloudflare.api.account.zone."
ALL_ACCOUNT_RESOURCES = {
    "com.cloudflare.api.account.*",
    "com.cloudflare.api.account.zone.*",
}


class Account(CloudflareService):
    """Retrieve Cloudflare account settings, members and API tokens.

    Data that could not be retrieved is tracked per account (``*_failed_accounts``)
    so checks can report it as MANUAL instead of silently omitting it.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.accounts: list["CloudflareAccountSettings"] = []
        self.members: list["CloudflareAccountMember"] = []
        self.tokens: list["CloudflareAPIToken"] = []
        self.settings_failed_accounts: set[str] = set()
        self.members_listed_accounts: set[str] = set()
        self.members_failed_accounts: set[str] = set()
        self.tokens_failed_accounts: set[str] = set()
        # Accounts for which zone-scoped user tokens could not be attributed
        # because the zone lookup failed.
        self.user_tokens_unattributed_accounts: set[str] = set()
        # None: not fetched yet; False: the zone listing failed.
        self._zone_accounts: Any = None
        self._get_accounts()
        self._list_members()
        self._list_account_tokens()
        self._list_user_tokens()

    @property
    def audited_accounts(self) -> list[str]:
        return list(self.provider.identity.audited_accounts)

    def _get_accounts(self) -> None:
        """Retrieve settings for every audited account."""
        logger.info("Account - Getting account settings...")
        account_names = {
            account.id: account.name for account in self.provider.identity.accounts
        }
        for account_id in self.audited_accounts:
            try:
                account = self.client.accounts.get(account_id=account_id)
                settings = getattr(account, "settings", None)
                self.accounts.append(
                    CloudflareAccountSettings(
                        id=account_id,
                        name=getattr(account, "name", None)
                        or account_names.get(account_id, account_id),
                        enforce_twofactor=getattr(settings, "enforce_twofactor", None),
                    )
                )
            except Exception as error:
                self.settings_failed_accounts.add(account_id)
                logger.error(
                    f"{account_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _list_members(self) -> None:
        """List members of every audited account.

        A listing that fails on any page is discarded entirely, so checks never
        evaluate an incomplete member list.
        """
        logger.info("Account - Listing account members...")
        for account_id in self.audited_accounts:
            try:
                raw_members = collect_pages(
                    self.client.accounts.members.list(account_id=account_id)
                )
            except Exception as error:
                self.members_failed_accounts.add(account_id)
                logger.error(
                    f"{account_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                continue

            self.members_listed_accounts.add(account_id)
            for member in raw_members:
                member_id = getattr(member, "id", None)
                if not member_id:
                    continue
                user = getattr(member, "user", None)
                roles = {
                    role_name
                    for role in getattr(member, "roles", None) or []
                    if (role_name := getattr(role, "name", None))
                }
                # Members managed through policies expose roles as permission groups
                for policy in getattr(member, "policies", None) or []:
                    if getattr(policy, "access", None) == "deny":
                        continue
                    for group in getattr(policy, "permission_groups", None) or []:
                        if group_name := getattr(group, "name", None):
                            roles.add(group_name)

                email = getattr(user, "email", None) if user else None
                self.members.append(
                    CloudflareAccountMember(
                        id=member_id,
                        name=email or member_id,
                        email=email,
                        account_id=account_id,
                        status=getattr(member, "status", None),
                        two_factor_enabled=(
                            getattr(user, "two_factor_authentication_enabled", None)
                            if user
                            else None
                        ),
                        roles=sorted(roles),
                    )
                )

    def _list_account_tokens(self) -> None:
        """List account-owned API tokens (requires Account API Tokens Read)."""
        logger.info("Account - Listing account-owned API tokens...")
        for account_id in self.audited_accounts:
            try:
                tokens = collect_pages(
                    self.client.accounts.tokens.list(account_id=account_id)
                )
            except Exception as error:
                self.tokens_failed_accounts.add(account_id)
                logger.warning(
                    f"{account_id} account tokens -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                continue
            for token in tokens:
                self._add_token(token, "account", account_id)

    def _list_user_tokens(self) -> None:
        """List the authenticated user's API tokens (optional API Tokens Read).

        User tokens are only reported for the audited accounts their policies
        grant access to, so they are never attributed to an unrelated account.
        """
        logger.info("Account - Listing user API tokens...")
        try:
            tokens = collect_pages(self.client.user.tokens.list())
        except Exception as error:
            # Optional permission: account-scoped scan tokens cannot list them.
            logger.warning(
                f"user tokens -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return
        for token in tokens:
            accounts = self._token_audited_accounts(token)
            if not accounts:
                logger.debug(
                    f"Skipping user token {getattr(token, 'id', '')}: no audited account in its policies."
                )
                continue
            self._add_token(token, "user", accounts[0])

    def _token_audited_accounts(self, token: Any) -> list[str]:
        """Return the audited accounts a token's allow policies grant access to.

        Policy resources may nest, e.g. ``{"...account.<id>": {"...account.zone.*": "*"}}``
        limits the zone wildcard to that account, so wildcards are resolved
        within their parent account scope.
        """
        audited = self.audited_accounts
        matched: set[str] = set()
        for policy in getattr(token, "policies", None) or []:
            if getattr(policy, "effect", "allow") == "deny":
                continue
            matched |= self._resource_accounts(
                getattr(policy, "resources", None), set(audited)
            )
        return [account_id for account_id in audited if account_id in matched]

    def _resource_accounts(self, resources: Any, scope: set[str]) -> set[str]:
        """Resolve the accounts covered by a (possibly nested) resources map.

        Args:
            resources: Policy resources: a dict of resource key to "*" or to a
                nested resources dict.
            scope: Accounts the enclosing resource limits this level to.

        Returns:
            The accounts, within ``scope``, that the resources grant access to.
        """
        matched: set[str] = set()
        if not isinstance(resources, dict):
            return matched
        for key, value in resources.items():
            if key in ALL_ACCOUNT_RESOURCES:
                accounts = set(scope)
            elif key.startswith(ZONE_RESOURCE_PREFIX):
                zone_id = key[len(ZONE_RESOURCE_PREFIX) :]
                zone_map = self._zone_account_map()
                if zone_map is None:
                    # Zones could not be listed: the token cannot be attributed.
                    self.user_tokens_unattributed_accounts |= scope
                    accounts = set()
                else:
                    account_id = zone_map.get(zone_id)
                    accounts = {account_id} & scope if account_id else set()
            elif key.startswith(ACCOUNT_RESOURCE_PREFIX):
                accounts = {key[len(ACCOUNT_RESOURCE_PREFIX) :]} & scope
            else:
                accounts = set()
            if isinstance(value, dict):
                # A nested map narrows the grant to its parent's accounts.
                matched |= self._resource_accounts(value, accounts)
            else:
                matched |= accounts
        return matched

    def _zone_account_map(self) -> Optional[dict[str, str]]:
        """Map zone IDs to account IDs, fetched once when a token is zone-scoped.

        Returns:
            The map, or None when the zones could not be listed.
        """
        if self._zone_accounts is None:
            try:
                zone_accounts = {}
                for zone in collect_pages(self.client.zones.list()):
                    account = getattr(zone, "account", None)
                    if getattr(zone, "id", None) and getattr(account, "id", None):
                        zone_accounts[zone.id] = account.id
                self._zone_accounts = zone_accounts
            except Exception as error:
                self._zone_accounts = False
                logger.warning(
                    f"zones -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return None if self._zone_accounts is False else self._zone_accounts

    def _add_token(self, token: Any, owner: str, account_id: str) -> None:
        token_id = getattr(token, "id", None)
        if not token_id:
            return
        condition = getattr(token, "condition", None)
        request_ip = getattr(condition, "request_ip", None) if condition else None
        self.tokens.append(
            CloudflareAPIToken(
                id=token_id,
                name=getattr(token, "name", None) or token_id,
                owner=owner,
                account_id=account_id,
                status=getattr(token, "status", None),
                ip_allow_list=(
                    (getattr(request_ip, "in_", None) or []) if request_ip else []
                ),
                ip_deny_list=(
                    (getattr(request_ip, "not_in", None) or []) if request_ip else []
                ),
                issued_on=getattr(token, "issued_on", None),
                expires_on=getattr(token, "expires_on", None),
                last_used_on=getattr(token, "last_used_on", None),
            )
        )


class CloudflareAccountSettings(BaseModel):
    """Cloudflare account and its security settings."""

    id: str
    name: str
    enforce_twofactor: Optional[bool] = None
    is_global_resource: ClassVar[bool] = True

    @property
    def account_id(self) -> str:
        return self.id


class CloudflareAccountMember(BaseModel):
    """Cloudflare account member."""

    id: str
    name: str
    email: Optional[str] = None
    account_id: str
    status: Optional[str] = None
    two_factor_enabled: Optional[bool] = None
    roles: list[str] = Field(default_factory=list)
    is_global_resource: ClassVar[bool] = True

    @property
    def is_super_admin(self) -> bool:
        return SUPER_ADMIN_ROLE_NAME in self.roles


class CloudflareAPIToken(BaseModel):
    """Cloudflare API token (user-owned or account-owned)."""

    id: str
    name: str
    owner: str  # "user" or "account"
    account_id: str = ""
    status: Optional[str] = None
    ip_allow_list: list[str] = Field(default_factory=list)
    ip_deny_list: list[str] = Field(default_factory=list)
    issued_on: Optional[datetime] = None
    expires_on: Optional[datetime] = None
    last_used_on: Optional[datetime] = None
    is_global_resource: ClassVar[bool] = True

    @property
    def unique_name(self) -> str:
        """Token name with its ID. Token names are not unique (dashboard
        templates reuse names such as "Edit zone DNS") and the finding UID is
        derived from the resource name."""
        return f"{self.name} ({self.id})" if self.name != self.id else self.id
