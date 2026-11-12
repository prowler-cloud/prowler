from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.r2.r2_client import r2_client
from prowler.providers.cloudflare.services.r2.r2_manual import r2_manual_reports

INSECURE_TLS_VERSIONS = {"1.0", "1.1"}
# Cloudflare applies TLS 1.0 as the minimum when minTLS is not set on a custom domain.
DEFAULT_MIN_TLS = "1.0"


class r2_bucket_custom_domain_min_tls_secure(Check):
    """Ensure that custom domains serving R2 buckets require TLS 1.2 or higher."""

    def execute(self) -> list[CheckReportCloudflare]:
        """Evaluate the minimum TLS version of every enabled R2 custom domain.

        Returns:
            PASS when all enabled custom domains of a bucket require TLS 1.2 or
            higher, FAIL otherwise, and MANUAL per account whose R2 data could
            not be retrieved. Buckets without enabled custom domains are skipped.
        """
        findings = r2_manual_reports(
            self,
            r2_client,
            r2_client.custom_domains_failed_accounts,
            "custom domain TLS",
        )
        for bucket in r2_client.buckets:
            domains = [d for d in bucket.custom_domains or [] if d.enabled]
            if not domains:
                continue
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=bucket,
                resource_name=bucket.unique_name,
            )
            insecure = sorted(
                f"{d.domain} (TLS {d.min_tls or DEFAULT_MIN_TLS})"
                for d in domains
                if (d.min_tls or DEFAULT_MIN_TLS) in INSECURE_TLS_VERSIONS
            )
            if insecure:
                report.status = "FAIL"
                report.status_extended = f"R2 bucket {bucket.unique_name} has custom domains accepting TLS versions below 1.2: {', '.join(insecure)}."
            else:
                report.status = "PASS"
                report.status_extended = f"R2 bucket {bucket.unique_name} custom domains require TLS 1.2 or higher."
            findings.append(report)
        return findings
