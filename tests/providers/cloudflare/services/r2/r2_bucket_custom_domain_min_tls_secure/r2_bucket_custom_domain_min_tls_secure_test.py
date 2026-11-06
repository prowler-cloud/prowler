from prowler.providers.cloudflare.services.r2.r2_service import (
    CloudflareR2CustomDomain,
)
from tests.providers.cloudflare.cloudflare_fixtures import ACCOUNT_ID
from tests.providers.cloudflare.services.r2.cloudflare_r2_check_helpers import (
    BUCKET,
    make_bucket,
    run_r2_check,
)

CHECK = "r2_bucket_custom_domain_min_tls_secure"


def _domain(name, min_tls, enabled=True):
    return CloudflareR2CustomDomain(domain=name, enabled=enabled, min_tls=min_tls)


class Test_r2_bucket_custom_domain_min_tls_secure:

    def test_no_resources(self):
        assert run_r2_check(CHECK, []) == []

    def test_enabled_insecure_domain_next_to_disabled_domain(self):
        domains = [
            _domain("old.example.com", "1.0", False),
            _domain("new.example.com", "1.1"),
        ]
        result = run_r2_check(CHECK, [make_bucket(custom_domains=domains)])
        assert len(result) == 1
        assert result[0].status == "FAIL"
        # the disabled domain is not reported
        assert "old.example.com" not in result[0].status_extended
        assert "new.example.com (TLS 1.1)" in result[0].status_extended

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

    def test_no_or_disabled_domains_skipped(self):
        buckets = [
            make_bucket(),
            make_bucket(custom_domains=[]),
            make_bucket(custom_domains=[_domain("old.example.com", "1.0", False)]),
        ]
        assert run_r2_check(CHECK, buckets) == []

    def test_pass(self):
        domains = [_domain("a.example.com", "1.2"), _domain("b.example.com", "1.3")]
        result = run_r2_check(CHECK, [make_bucket(custom_domains=domains)])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"R2 bucket {BUCKET} custom domains require TLS 1.2 or higher."
        )

    def test_fail_explicit_and_default(self):
        domains = [
            _domain("a.example.com", "1.2"),
            _domain("b.example.com", "1.1"),
            _domain("c.example.com", None),
        ]
        result = run_r2_check(CHECK, [make_bucket(custom_domains=domains)])
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"R2 bucket {BUCKET} has custom domains accepting TLS versions below 1.2: b.example.com (TLS 1.1), c.example.com (TLS 1.0)."
        )
