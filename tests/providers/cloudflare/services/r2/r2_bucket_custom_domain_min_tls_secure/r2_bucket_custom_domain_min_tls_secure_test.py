from prowler.providers.cloudflare.services.r2.r2_service import (
    CloudflareR2CustomDomain,
)
from tests.providers.cloudflare.services.r2.cloudflare_r2_check_helpers import (
    BUCKET,
    make_bucket,
    run_r2_check,
)

CHECK = "r2_bucket_custom_domain_min_tls_secure"


def _domain(name, min_tls, enabled=True):
    return CloudflareR2CustomDomain(domain=name, enabled=enabled, min_tls=min_tls)


class Test_r2_bucket_custom_domain_min_tls_secure:
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
