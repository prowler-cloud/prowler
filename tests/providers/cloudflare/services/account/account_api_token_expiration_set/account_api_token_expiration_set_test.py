from datetime import datetime, timezone

from tests.providers.cloudflare.cloudflare_fixtures import ACCOUNT_ID, ACCOUNT_NAME
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

    def test_account_tokens_listing_failed_manual(self):
        result = run_account_check(CHECK, tokens_failed=[ACCOUNT_ID])
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == ACCOUNT_ID
        assert (
            result[0].status_extended
            == f"Cannot evaluate expiration dates for account-owned API tokens of account {ACCOUNT_NAME}: the tokens could not be listed. Account-owned tokens are only visible to tokens created by a Super Administrator with the Account API Tokens Read permission."
        )

    def test_unattributed_user_tokens_manual(self):
        result = run_account_check(CHECK, user_tokens_unattributed=[ACCOUNT_ID])
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"Cannot evaluate expiration dates for zone-scoped user API tokens of account {ACCOUNT_NAME}: the zones could not be listed to attribute them to an account. Verify that the scanning token has the Zone Read permission."
        )

    def test_inactive_tokens_skipped(self):
        tokens = [make_token(status="disabled"), make_token(status="expired")]
        assert run_account_check(CHECK, tokens=tokens) == []

    def test_pass(self):
        expires = datetime(2027, 1, 1, tzinfo=timezone.utc)
        result = run_account_check(CHECK, tokens=[make_token(expires_on=expires)])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == TOKEN_ID
        # token names are not unique, so the ID is part of the resource name
        assert result[0].resource_name == f"{TOKEN_NAME} ({TOKEN_ID})"
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
