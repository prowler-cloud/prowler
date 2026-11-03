from prowler.providers.cloudflare.services.account.account_service import (
    CloudflareAccountMember,
)
from tests.providers.cloudflare.cloudflare_fixtures import ACCOUNT_ID, ACCOUNT_NAME
from tests.providers.cloudflare.services.account.cloudflare_account_check_helpers import (
    run_account_check,
)

CHECK = "account_member_two_factor_enabled"
EMAIL = "user@example.com"


def _member(two_fa, status="accepted"):
    return CloudflareAccountMember(
        id="member-1",
        name=EMAIL,
        email=EMAIL,
        account_id=ACCOUNT_ID,
        status=status,
        two_factor_enabled=two_fa,
    )


class Test_account_member_two_factor_enabled:
    def test_no_members(self):
        assert run_account_check(CHECK) == []

    def test_pending_skipped(self):
        assert (
            run_account_check(CHECK, members=[_member(False, status="pending")]) == []
        )

    def test_unknown_2fa_status_one_account_manual(self):
        members = [_member(None), _member(None)]
        result = run_account_check(CHECK, members=members)
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == ACCOUNT_ID
        assert "did not return their 2FA status" in result[0].status_extended

    def test_members_listing_failed_manual(self):
        result = run_account_check(CHECK, members_failed=[ACCOUNT_ID])
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"Cannot evaluate member two-factor authentication for account {ACCOUNT_NAME}: the account members could not be listed. Verify that the scanning token has the Account Settings Read permission."
        )

    def test_pass(self):
        result = run_account_check(CHECK, members=[_member(True)])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == "member-1"
        assert result[0].resource_name == EMAIL
        assert result[0].account_id == ACCOUNT_ID
        assert (
            result[0].status_extended
            == f"Account member {EMAIL} has two-factor authentication enabled."
        )

    def test_fail(self):
        result = run_account_check(CHECK, members=[_member(False)])
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Account member {EMAIL} does not have two-factor authentication enabled."
        )
