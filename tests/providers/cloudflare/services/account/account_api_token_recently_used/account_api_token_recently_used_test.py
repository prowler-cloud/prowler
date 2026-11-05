from datetime import datetime, timedelta, timezone

from tests.providers.cloudflare.services.account.cloudflare_account_check_helpers import (
    run_account_check,
)
from tests.providers.cloudflare.services.account.cloudflare_account_token_factory import (
    TOKEN_NAME,
    make_token,
)

CHECK = "account_api_token_recently_used"
NOW = datetime.now(timezone.utc)
LABEL = f"API token {TOKEN_NAME} (account-owned)"


class Test_account_api_token_recently_used:
    def test_no_tokens(self):
        assert run_account_check(CHECK) == []

    def test_inactive_skipped(self):
        assert run_account_check(CHECK, tokens=[make_token(status="expired")]) == []

    def test_recently_used_pass(self):
        used = NOW - timedelta(days=5)
        result = run_account_check(CHECK, tokens=[make_token(last_used_on=used)])
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"{LABEL} was last used on {used.date().isoformat()}, within the last 90 days."
        )

    def test_naive_datetime_handled(self):
        used = (NOW - timedelta(days=5)).replace(tzinfo=None)
        result = run_account_check(CHECK, tokens=[make_token(last_used_on=used)])
        assert result[0].status == "PASS"

    def test_stale_fail_custom_window(self):
        used = NOW - timedelta(days=40)
        result = run_account_check(
            CHECK,
            tokens=[make_token(last_used_on=used)],
            audit_config={"max_unused_api_token_days": 30},
        )
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"{LABEL} has not been used since {used.date().isoformat()}, more than 30 days ago."
        )

    def test_never_used_new_token_pass(self):
        result = run_account_check(
            CHECK, tokens=[make_token(issued_on=NOW - timedelta(days=1))]
        )
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"{LABEL} has never been used but was issued within the last 90 days."
        )

    def test_never_used_old_token_fail(self):
        result = run_account_check(
            CHECK, tokens=[make_token(issued_on=NOW - timedelta(days=200))]
        )
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"{LABEL} has never been used and was issued more than 90 days ago."
        )

    def test_never_used_unknown_issue_date_manual(self):
        result = run_account_check(CHECK, tokens=[make_token()])
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"{LABEL} has no recorded use or issue date; review whether it is still needed."
        )

    def test_null_threshold_uses_default(self):
        used = NOW - timedelta(days=60)
        result = run_account_check(
            CHECK,
            tokens=[make_token(last_used_on=used)],
            audit_config={"max_unused_api_token_days": None},
        )
        assert result[0].status == "PASS"
        assert "within the last 90 days" in result[0].status_extended
