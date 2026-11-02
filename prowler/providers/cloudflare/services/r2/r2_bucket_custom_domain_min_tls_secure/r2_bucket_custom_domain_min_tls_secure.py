from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.r2.r2_client import r2_client

INSECURE_TLS_VERSIONS = {"1.0", "1.1"}
# Cloudflare applies TLS 1.0 as the minimum when minTLS is not set on a custom domain.
DEFAULT_MIN_TLS = "1.0"


class r2_bucket_custom_domain_min_tls_secure(Check):
    """Ensure that custom domains serving R2 buckets require TLS 1.2 or higher."""

    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for bucket in r2_client.buckets:
            domains = [d for d in bucket.custom_domains or [] if d.enabled]
            if not domains:
                continue
            report = CheckReportCloudflare(metadata=self.metadata(), resource=bucket)
            insecure = sorted(
                f"{d.domain} (TLS {d.min_tls or DEFAULT_MIN_TLS})"
                for d in domains
                if (d.min_tls or DEFAULT_MIN_TLS) in INSECURE_TLS_VERSIONS
            )
            if insecure:
                report.status = "FAIL"
                report.status_extended = f"R2 bucket {bucket.name} has custom domains accepting TLS versions below 1.2: {', '.join(insecure)}."
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"R2 bucket {bucket.name} custom domains require TLS 1.2 or higher."
                )
            findings.append(report)
        return findings
