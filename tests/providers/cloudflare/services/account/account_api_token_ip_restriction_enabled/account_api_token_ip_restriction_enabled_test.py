from tests.providers.cloudflare.services.account.cloudflare_account_check_helpers import (
    run_account_check,
)
from tests.providers.cloudflare.services.account.cloudflare_account_token_factory import (
    TOKEN_NAME,
    make_token,
)

CHECK = "account_api_token_ip_restriction_enabled"


class Test_account_api_token_ip_restriction_enabled:
    def test_no_tokens(self):
        assert run_account_check(CHECK) == []

    def test_inactive_skipped(self):
        assert run_account_check(CHECK, tokens=[make_token(status="disabled")]) == []

    def test_pass_allow_list(self):
        result = run_account_check(
            CHECK, tokens=[make_token(ip_allow_list=["192.0.2.0/24"])]
        )
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"API token {TOKEN_NAME} (account-owned) has client IP address filtering configured."
        )

    def test_pass_deny_list(self):
        result = run_account_check(
            CHECK, tokens=[make_token(ip_deny_list=["10.0.0.0/8"])]
        )
        assert result[0].status == "PASS"

    def test_fail(self):
        result = run_account_check(CHECK, tokens=[make_token()])
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"API token {TOKEN_NAME} (account-owned) does not have client IP address filtering configured."
        )
