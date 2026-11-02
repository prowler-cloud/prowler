from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.cloudflare.lib.service.service import CloudflareService

SUPER_ADMIN_ROLE_NAME = "Super Administrator - All Privileges"


class Account(CloudflareService):
    """Retrieve Cloudflare account settings, members and API tokens."""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.accounts: list["CloudflareAccountSettings"] = []
        self.members: list["CloudflareAccountMember"] = []
        self.tokens: list["CloudflareAPIToken"] = []
        self._get_accounts()
        self._list_members()
        self._list_account_tokens()
        self._list_user_tokens()

    def _get_accounts(self) -> None:
        """Retrieve settings for every audited account."""
        logger.info("Account - Getting account settings...")
        account_names = {
            account.id: account.name for account in self.provider.identity.accounts
        }
        for account_id in self.provider.identity.audited_accounts:
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
                logger.error(
                    f"{account_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _list_members(self) -> None:
        """List members of every audited account."""
        logger.info("Account - Listing account members...")
        for account_id in self.provider.identity.audited_accounts:
            try:
                seen_member_ids: set[str] = set()
                for member in self.client.accounts.members.list(account_id=account_id):
                    member_id = getattr(member, "id", None)
                    if not member_id or member_id in seen_member_ids:
                        continue
                    seen_member_ids.add(member_id)

                    user = getattr(member, "user", None)
                    roles = {
                        role_name
                        for role in getattr(member, "roles", None) or []
                        if (role_name := getattr(role, "name", None))
                    }
                    # Members managed through policies expose roles as permission groups
                    for policy in getattr(member, "policies", None) or []:
                        if getattr(policy, "access", "allow") != "allow":
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
            except Exception as error:
                logger.error(
                    f"{account_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _list_account_tokens(self) -> None:
        """List account-owned API tokens (requires Account API Tokens Read)."""
        logger.info("Account - Listing account-owned API tokens...")
        for account_id in self.provider.identity.audited_accounts:
            try:
                for token in self.client.accounts.tokens.list(account_id=account_id):
                    self._add_token(token, owner="account", account_id=account_id)
            except Exception as error:
                logger.warning(
                    f"{account_id} account tokens -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _list_user_tokens(self) -> None:
        """List the authenticated user's API tokens (requires API Tokens Read)."""
        logger.info("Account - Listing user API tokens...")
        try:
            for token in self.client.user.tokens.list():
                self._add_token(token, owner="user", account_id="")
        except Exception as error:
            logger.warning(
                f"user tokens -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _add_token(self, token, owner: str, account_id: str) -> None:
        token_id = getattr(token, "id", None)
        if not token_id or any(
            existing.id == token_id and existing.owner == owner
            for existing in self.tokens
        ):
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
