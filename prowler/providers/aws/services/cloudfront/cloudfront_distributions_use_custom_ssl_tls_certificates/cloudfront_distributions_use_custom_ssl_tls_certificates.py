from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudfront.cloudfront_client import (
    cloudfront_client,
)


class cloudfront_distributions_using_deprecated_ssl_protocols(Check):
    def execute(self):
        findings = []
        for distribution in cloudfront_client.distributions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = distribution.region
            report.resource_arn = distribution.arn
            report.resource_id = distribution.id
            report.resource_tags = distribution.tags
            report.status = "PASS"
            report.status_extended = f"CloudFront Distribution {distribution.id} is using custom SSL/TLS certificates."

            if distribution.default_certificate:
                report.status = "FAIL"
                report.status_extended = f"CloudFront Distribution {distribution.id} is using default SSL/TLS certificates."

            findings.append(report)

        return findings
