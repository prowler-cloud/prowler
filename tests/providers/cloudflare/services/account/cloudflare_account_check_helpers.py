from unittest import mock

from tests.providers.cloudflare.cloudflare_fixtures import (
    set_mocked_cloudflare_provider,
)


def run_account_check(
    check_name, accounts=None, members=None, tokens=None, audit_config=None
):
    account_client = mock.MagicMock()
    account_client.accounts = accounts or []
    account_client.members = members or []
    account_client.tokens = tokens or []
    account_client.audit_config = audit_config or {}
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
