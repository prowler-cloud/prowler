from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.r2.r2_client import r2_client
from prowler.providers.cloudflare.services.r2.r2_manual import r2_manual_reports


class r2_bucket_public_dev_url_disabled(Check):
    """Ensure that R2 buckets are not publicly readable through their r2.dev URL.

    Enabling the r2.dev development URL makes every object in the bucket
    readable by anyone on the internet, without authentication, caching, WAF or
    access controls.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Evaluate whether every R2 bucket is publicly readable through r2.dev.

        Returns:
            PASS when r2.dev access is disabled, FAIL when it is enabled, and
            MANUAL per account whose R2 data could not be retrieved.
        """
        findings = r2_manual_reports(
            self, r2_client, r2_client.dev_url_failed_accounts, "public r2.dev access"
        )
        for bucket in r2_client.buckets:
            if bucket.public_dev_url_enabled is None:
                continue
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=bucket,
                resource_name=bucket.unique_name,
            )
            if bucket.public_dev_url_enabled:
                report.status = "FAIL"
                report.status_extended = f"R2 bucket {bucket.unique_name} is publicly readable through its r2.dev URL{f' ({bucket.public_dev_url})' if bucket.public_dev_url else ''}."
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"R2 bucket {bucket.unique_name} has public r2.dev access disabled."
                )
            findings.append(report)
        return findings
