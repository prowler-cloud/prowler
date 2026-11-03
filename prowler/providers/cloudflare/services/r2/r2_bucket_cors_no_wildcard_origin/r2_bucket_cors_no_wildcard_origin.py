from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.r2.r2_client import r2_client


class r2_bucket_cors_no_wildcard_origin(Check):
    """Ensure that R2 bucket CORS policies do not allow any origin."""

    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for bucket in r2_client.buckets:
            if bucket.cors_rules is None:
                continue
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=bucket,
                resource_name=bucket.unique_name,
            )
            wildcard_methods = sorted(
                {
                    method
                    for rule in bucket.cors_rules
                    if "*" in rule.origins
                    for method in rule.methods
                }
            )
            wildcard = any("*" in rule.origins for rule in bucket.cors_rules)
            if wildcard:
                report.status = "FAIL"
                report.status_extended = f"R2 bucket {bucket.unique_name} has a CORS rule allowing any origin (*) for methods: {', '.join(wildcard_methods) or 'none'}."
            else:
                report.status = "PASS"
                report.status_extended = f"R2 bucket {bucket.unique_name} has no CORS rule allowing any origin."
            findings.append(report)
        return findings
