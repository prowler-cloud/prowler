from prowler.providers.cloudflare.services.account.account_service import (
    SUPER_ADMIN_ROLE_NAME,
    CloudflareAccountMember,
    CloudflareAccountSettings,
)
from tests.providers.cloudflare.cloudflare_fixtures import ACCOUNT_ID, ACCOUNT_NAME
from tests.providers.cloudflare.services.account.cloudflare_account_check_helpers import (
    run_account_check,
)

CHECK = "account_super_admins_limited"
ACCOUNT = CloudflareAccountSettings(id=ACCOUNT_ID, name=ACCOUNT_NAME)


def _members(super_admins, others=1, pending_super_admins=0):
    members = []
    for i in range(super_admins):
        members.append(
            CloudflareAccountMember(
                id=f"sa-{i}",
                name=f"sa{i}@example.com",
                account_id=ACCOUNT_ID,
                status="accepted",
                roles=[SUPER_ADMIN_ROLE_NAME],
            )
        )
    for i in range(pending_super_admins):
        members.append(
            CloudflareAccountMember(
                id=f"pending-{i}",
                name=f"pending{i}@example.com",
                account_id=ACCOUNT_ID,
                status="pending",
                roles=[SUPER_ADMIN_ROLE_NAME],
            )
        )
    for i in range(others):
        members.append(
            CloudflareAccountMember(
                id=f"m-{i}",
                name=f"m{i}@example.com",
                account_id=ACCOUNT_ID,
                status="accepted",
                roles=["Administrator"],
            )
        )
    return members


class Test_account_super_admins_limited:
    def test_no_members_listed_skipped(self):
        assert run_account_check(CHECK, accounts=[ACCOUNT], members_listed=[]) == []

    def test_successful_empty_member_list_counts_zero(self):
        result = run_account_check(
            CHECK, accounts=[ACCOUNT], members_listed=[ACCOUNT_ID]
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert "has 0 Super Administrator(s)" in result[0].status_extended

    def test_members_listing_failed_manual(self):
        result = run_account_check(
            CHECK, accounts=[ACCOUNT], members_failed=[ACCOUNT_ID]
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be listed" in result[0].status_extended

    def test_null_threshold_uses_default(self):
        result = run_account_check(
            CHECK,
            accounts=[ACCOUNT],
            members=_members(3),
            audit_config={"max_super_admins": None},
        )
        assert result[0].status == "PASS"
        assert "within the limit of 3" in result[0].status_extended

    def test_pass_default_limit(self):
        result = run_account_check(
            CHECK,
            accounts=[ACCOUNT],
            members=_members(3, pending_super_admins=2),
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == ACCOUNT_ID
        assert (
            result[0].status_extended
            == f"Account {ACCOUNT_NAME} has 3 Super Administrator(s), within the limit of 3."
        )

    def test_fail_custom_limit(self):
        result = run_account_check(
            CHECK,
            accounts=[ACCOUNT],
            members=_members(2),
            audit_config={"max_super_admins": 1},
        )
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Account {ACCOUNT_NAME} has 2 Super Administrators, exceeding the limit of 1: sa0@example.com, sa1@example.com."
        )
