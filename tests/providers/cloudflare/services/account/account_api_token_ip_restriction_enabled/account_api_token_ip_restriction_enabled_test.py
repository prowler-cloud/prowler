from tests.providers.cloudflare.services.account.cloudflare_account_check_helpers import (
    run_account_check,
)
from tests.providers.cloudflare.services.account.cloudflare_account_token_factory import (
    TOKEN_ID,
    TOKEN_NAME,
    make_token,
)

CHECK = "account_api_token_ip_restriction_enabled"
LABEL = f"API token {TOKEN_NAME} (account-owned)"


class Test_account_api_token_ip_restriction_enabled:
    def test_no_tokens(self):
        assert run_account_check(CHECK) == []

    def test_inactive_skipped(self):
        assert run_account_check(CHECK, tokens=[make_token(status="disabled")]) == []

    def test_pass_allow_list(self):
        result = run_account_check(
            CHECK,
            tokens=[
                make_token(
                    ip_allow_list=["192.0.2.0/24"], ip_deny_list=["192.0.2.7/32"]
                )
            ],
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == TOKEN_ID
        assert result[0].resource_name == f"{TOKEN_NAME} ({TOKEN_ID})"
        assert (
            result[0].status_extended
            == f"{LABEL} is restricted to an allow-list of client IP addresses."
        )

    def test_fail_no_filtering(self):
        result = run_account_check(CHECK, tokens=[make_token()])
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"{LABEL} does not have client IP address filtering configured."
        )

    def test_fail_deny_list_only(self):
        # A deny-list alone still lets the token be used from every other address
        result = run_account_check(
            CHECK, tokens=[make_token(ip_deny_list=["203.0.113.5/32"])]
        )
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"{LABEL} only denies specific client IP addresses and can be used from any other address."
        )

    def test_fail_allow_list_any_address(self):
        result = run_account_check(
            CHECK,
            tokens=[make_token(ip_allow_list=["192.0.2.0/24", "0.0.0.0/0", "::/0"])],
        )
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"{LABEL} allows client IP addresses from any address (0.0.0.0/0, ::/0)."
        )

    def test_tokens_with_same_name_get_distinct_resource_names(self):
        result = run_account_check(
            CHECK,
            tokens=[
                make_token(id="token-a", name="Edit zone DNS"),
                make_token(id="token-b", name="Edit zone DNS"),
            ],
        )
        assert {r.resource_name for r in result} == {
            "Edit zone DNS (token-a)",
            "Edit zone DNS (token-b)",
        }
