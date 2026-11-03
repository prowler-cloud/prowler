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
        self._zone_accounts: Optional[dict[str, str]] = None
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
        """Return the audited accounts a token's allow policies grant access to."""
        audited = self.audited_accounts
        matched: set[str] = set()
        for policy in getattr(token, "policies", None) or []:
            if getattr(policy, "effect", "allow") == "deny":
                continue
            for resource in _resource_keys(getattr(policy, "resources", None)):
                if resource in ALL_ACCOUNT_RESOURCES:
                    matched.update(audited)
                elif resource.startswith(ZONE_RESOURCE_PREFIX):
                    zone_id = resource[len(ZONE_RESOURCE_PREFIX) :]
                    account_id = self._zone_account_map().get(zone_id)
                    if account_id:
                        matched.add(account_id)
                elif resource.startswith(ACCOUNT_RESOURCE_PREFIX):
                    matched.add(resource[len(ACCOUNT_RESOURCE_PREFIX) :])
        return [account_id for account_id in audited if account_id in matched]

    def _zone_account_map(self) -> dict[str, str]:
        """Map zone IDs to account IDs (only fetched when a token is zone-scoped)."""
        if self._zone_accounts is None:
            self._zone_accounts = {}
            try:
                for zone in collect_pages(self.client.zones.list()):
                    account = getattr(zone, "account", None)
                    if getattr(zone, "id", None) and getattr(account, "id", None):
                        self._zone_accounts[zone.id] = account.id
            except Exception as error:
                logger.warning(
                    f"zones -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return self._zone_accounts

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


def _resource_keys(resources: Any) -> list[str]:
    """Flatten token policy resources (keys may nest account -> zone maps)."""
    if not isinstance(resources, dict):
        return []
    keys = []
    for key, value in resources.items():
        keys.append(key)
        keys.extend(_resource_keys(value))
    return keys


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
