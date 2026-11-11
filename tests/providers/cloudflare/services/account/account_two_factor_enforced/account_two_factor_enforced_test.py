from prowler.providers.cloudflare.services.account.account_service import (
    CloudflareAccountSettings,
)
from tests.providers.cloudflare.cloudflare_fixtures import ACCOUNT_ID, ACCOUNT_NAME
from tests.providers.cloudflare.services.account.cloudflare_account_check_helpers import (
    run_account_check,
)

CHECK = "account_two_factor_enforced"


def _account(enforce):
    return CloudflareAccountSettings(
        id=ACCOUNT_ID, name=ACCOUNT_NAME, enforce_twofactor=enforce
    )


class Test_account_two_factor_enforced:
    def test_no_accounts(self):
        assert run_account_check(CHECK) == []

    def test_unknown_setting_manual(self):
        result = run_account_check(CHECK, accounts=[_account(None)])
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == ACCOUNT_ID
        assert result[0].region == "global"
        assert "Account Settings Read" in result[0].status_extended

    def test_settings_retrieval_failed_manual(self):
        result = run_account_check(CHECK, settings_failed=[ACCOUNT_ID])
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_name == ACCOUNT_NAME
        assert (
            result[0].status_extended
            == f"Cannot evaluate two-factor authentication enforcement for account {ACCOUNT_NAME}: the account settings could not be retrieved. Verify that the scanning token has the Account Settings Read permission."
        )

    def test_pass(self):
        result = run_account_check(CHECK, accounts=[_account(True)])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == ACCOUNT_ID
        assert result[0].resource_name == ACCOUNT_NAME
        assert result[0].account_id == ACCOUNT_ID
        assert (
            result[0].status_extended
            == f"Account {ACCOUNT_NAME} enforces two-factor authentication for all members."
        )

    def test_fail(self):
        result = run_account_check(CHECK, accounts=[_account(False)])
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Account {ACCOUNT_NAME} does not enforce two-factor authentication for its members."
        )
