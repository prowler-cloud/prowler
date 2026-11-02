from datetime import datetime, timezone

from tests.providers.cloudflare.cloudflare_fixtures import ACCOUNT_ID
from tests.providers.cloudflare.services.account.cloudflare_account_check_helpers import (
    run_account_check,
)
from tests.providers.cloudflare.services.account.cloudflare_account_token_factory import (
    TOKEN_ID,
    TOKEN_NAME,
    make_token,
)

CHECK = "account_api_token_expiration_set"


class Test_account_api_token_expiration_set:
    def test_no_tokens(self):
        assert run_account_check(CHECK) == []

    def test_inactive_tokens_skipped(self):
        tokens = [make_token(status="disabled"), make_token(status="expired")]
        assert run_account_check(CHECK, tokens=tokens) == []

    def test_pass(self):
        expires = datetime(2027, 1, 1, tzinfo=timezone.utc)
        result = run_account_check(CHECK, tokens=[make_token(expires_on=expires)])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == TOKEN_ID
        assert result[0].resource_name == TOKEN_NAME
        assert result[0].account_id == ACCOUNT_ID
        assert (
            result[0].status_extended
            == f"API token {TOKEN_NAME} (account-owned) expires on {expires.isoformat()}."
        )

    def test_fail_user_token(self):
        result = run_account_check(
            CHECK, tokens=[make_token(owner="user", account_id="")]
        )
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"API token {TOKEN_NAME} (user-owned) does not have an expiration date."
        )
