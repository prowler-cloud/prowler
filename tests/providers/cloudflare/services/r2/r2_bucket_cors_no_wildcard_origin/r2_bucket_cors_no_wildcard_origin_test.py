from prowler.providers.cloudflare.services.r2.r2_service import CloudflareR2CorsRule
from tests.providers.cloudflare.services.r2.cloudflare_r2_check_helpers import (
    BUCKET,
    make_bucket,
    run_r2_check,
)

CHECK = "r2_bucket_cors_no_wildcard_origin"


class Test_r2_bucket_cors_no_wildcard_origin:
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
