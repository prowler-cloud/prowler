from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudfront.cloudfront_client import (
    cloudfront_client,
)


class cloudfront_distributions_field_level_encryption_enabled(Check):
    def execute(self):
        findings = []
        for distribution in cloudfront_client.distributions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = distribution.region
            report.resource_arn = distribution.arn
            report.resource_id = distribution.id
            if distribution.default_cache_config.field_level_encryption_id:
                report.status = "PASS"
                report.status_extended = f"CloudFront Distribution {distribution.id} has Field Level Encryption enabled"
            else:
                report.status = "FAIL"
                report.status_extended = f"CloudFront Distribution {distribution.id} has Field Level Encryption disabled"

            findings.append(report)

        return findings
