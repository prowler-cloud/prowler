from datetime import datetime, timezone
from types import SimpleNamespace

from prowler.providers.cloudflare.services.account.account_service import (
    SUPER_ADMIN_ROLE_NAME,
    Account,
    CloudflareAccountMember,
)
from tests.providers.cloudflare.cloudflare_fixtures import (
    ACCOUNT_ID,
    ACCOUNT_NAME,
    set_mocked_cloudflare_provider,
)

ISSUED = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _token(token_id, **kwargs):
    defaults = dict(
        id=token_id,
        name=f"name-{token_id}",
        status="active",
        condition=None,
        issued_on=ISSUED,
        expires_on=None,
        last_used_on=None,
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def _provider():
    provider = set_mocked_cloudflare_provider()
    client = provider.session.client
    client.accounts.get.return_value = SimpleNamespace(
        id=ACCOUNT_ID,
        name=ACCOUNT_NAME,
        settings=SimpleNamespace(enforce_twofactor=True),
    )
    client.accounts.members.list.return_value = [
        SimpleNamespace(
            id="m1",
            status="accepted",
            user=SimpleNamespace(
                email="admin@example.com", two_factor_authentication_enabled=True
            ),
            roles=[SimpleNamespace(name=SUPER_ADMIN_ROLE_NAME)],
            policies=None,
        ),
        SimpleNamespace(
            id="m2",
            status="accepted",
            user=SimpleNamespace(
                email="dev@example.com", two_factor_authentication_enabled=False
            ),
            roles=None,
            policies=[
                SimpleNamespace(
                    access="allow",
                    permission_groups=[SimpleNamespace(name="Workers Admin")],
                ),
                SimpleNamespace(
                    access="deny",
                    permission_groups=[SimpleNamespace(name=SUPER_ADMIN_ROLE_NAME)],
                ),
            ],
        ),
        # duplicate
        SimpleNamespace(id="m1", status="accepted", user=None, roles=None),
    ]
    request_ip = SimpleNamespace(in_=["192.0.2.0/24"], not_in=None)
    client.accounts.tokens.list.return_value = [
        _token("acct-1", condition=SimpleNamespace(request_ip=request_ip))
    ]
    client.user.tokens.list.return_value = [_token("user-1"), _token("user-1")]
    return provider


class TestAccountService:
    def test_service(self):
        service = Account(_provider())

        assert service.service == "account"
        assert len(service.accounts) == 1
        assert service.accounts[0].id == ACCOUNT_ID
        assert service.accounts[0].account_id == ACCOUNT_ID
        assert service.accounts[0].name == ACCOUNT_NAME
        assert service.accounts[0].enforce_twofactor is True

        assert [m.id for m in service.members] == ["m1", "m2"]
        admin, dev = service.members
        assert admin.name == "admin@example.com"
        assert admin.account_id == ACCOUNT_ID
        assert admin.two_factor_enabled is True
        assert admin.is_super_admin is True
        assert dev.two_factor_enabled is False
        # deny policies must not grant roles
        assert dev.roles == ["Workers Admin"]
        assert dev.is_super_admin is False

        assert [(t.id, t.owner) for t in service.tokens] == [
            ("acct-1", "account"),
            ("user-1", "user"),
        ]
        account_token, user_token = service.tokens
        assert account_token.account_id == ACCOUNT_ID
        assert account_token.ip_allow_list == ["192.0.2.0/24"]
        assert account_token.ip_deny_list == []
        assert user_token.account_id == ""
        assert user_token.ip_allow_list == []

    def test_errors_are_handled(self):
        provider = set_mocked_cloudflare_provider()
        client = provider.session.client
        client.accounts.get.side_effect = Exception("boom")
        client.accounts.members.list.side_effect = Exception("boom")
        client.accounts.tokens.list.side_effect = Exception("forbidden")
        client.user.tokens.list.side_effect = Exception("forbidden")

        service = Account(provider)

        assert service.accounts == []
        assert service.members == []
        assert service.tokens == []

    def test_member_model_defaults(self):
        member = CloudflareAccountMember(id="m", name="m", account_id=ACCOUNT_ID)
        assert member.roles == []
        assert member.is_super_admin is False
        assert member.two_factor_enabled is None
