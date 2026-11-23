from prowler.providers.cloudflare.services.r2.r2_service import CloudflareR2CorsRule
from tests.providers.cloudflare.cloudflare_fixtures import ACCOUNT_ID
from tests.providers.cloudflare.services.r2.cloudflare_r2_check_helpers import (
    BUCKET,
    make_bucket,
    run_r2_check,
)

CHECK = "r2_bucket_cors_no_wildcard_origin"


class Test_r2_bucket_cors_no_wildcard_origin:

    def test_no_resources(self):
        assert run_r2_check(CHECK, []) == []

    def test_retrieval_failed_one_account_manual(self):
        result = run_r2_check(
            CHECK, [make_bucket(), make_bucket()], failed=[ACCOUNT_ID]
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == ACCOUNT_ID
        assert result[0].region == "global"
        assert "Workers R2 Storage Read" in result[0].status_extended

    def test_listing_failed_manual(self):
        result = run_r2_check(CHECK, [], list_failed=[ACCOUNT_ID])
        assert [r.status for r in result] == ["MANUAL"]

    def test_unknown_skipped(self):
        assert run_r2_check(CHECK, [make_bucket()]) == []

    def test_no_cors_policy_pass(self):
        result = run_r2_check(CHECK, [make_bucket(cors_rules=[])])
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"R2 bucket {BUCKET} has no CORS rule allowing any origin."
        )

    def test_explicit_origin_pass(self):
        rules = [
            CloudflareR2CorsRule(origins=["https://app.example.com"], methods=["GET"])
        ]
        result = run_r2_check(CHECK, [make_bucket(cors_rules=rules)])
        assert result[0].status == "PASS"

    def test_wildcard_fail(self):
        rules = [
            CloudflareR2CorsRule(origins=["https://a.example.com"], methods=["DELETE"]),
            CloudflareR2CorsRule(origins=["*"], methods=["PUT", "GET"]),
        ]
        result = run_r2_check(CHECK, [make_bucket(cors_rules=rules)])
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"R2 bucket {BUCKET} has a CORS rule allowing any origin (*) for methods: GET, PUT."
        )
