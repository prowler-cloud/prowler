from types import SimpleNamespace
from unittest import mock

from tests.providers.cloudflare.cloudflare_fixtures import (
    ACCOUNT_ID,
    ACCOUNT_NAME,
    set_mocked_cloudflare_provider,
)


def make_account_client(
    accounts=None,
    members=None,
    tokens=None,
    audit_config=None,
    settings_failed=(),
    members_failed=(),
    members_listed=None,
    tokens_failed=(),
    user_tokens_unattributed=(),
):
    client = mock.MagicMock()
    client.accounts = accounts or []
    client.members = members or []
    client.tokens = tokens or []
    client.audit_config = audit_config or {}
    client.audited_accounts = [ACCOUNT_ID]
    client.settings_failed_accounts = set(settings_failed)
    client.members_failed_accounts = set(members_failed)
    client.members_listed_accounts = (
        set(members_listed)
        if members_listed is not None
        else {m.account_id for m in client.members}
    )
    client.tokens_failed_accounts = set(tokens_failed)
    client.user_tokens_unattributed_accounts = set(user_tokens_unattributed)
    client.provider = SimpleNamespace(
        identity=SimpleNamespace(
            accounts=[SimpleNamespace(id=ACCOUNT_ID, name=ACCOUNT_NAME)]
        )
    )
    return client


def run_account_check(check_name, **kwargs):
    account_client = make_account_client(**kwargs)
    module = f"prowler.providers.cloudflare.services.account.{check_name}.{check_name}"
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_cloudflare_provider(),
        ),
        mock.patch(f"{module}.account_client", new=account_client),
    ):
        check_module = __import__(module, fromlist=[check_name])
        return getattr(check_module, check_name)().execute()
