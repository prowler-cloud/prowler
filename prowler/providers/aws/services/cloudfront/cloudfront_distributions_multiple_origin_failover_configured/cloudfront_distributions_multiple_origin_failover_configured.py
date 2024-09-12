from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudfront.cloudfront_client import (
    cloudfront_client,
)


class cloudfront_distributions_multiple_origin_failover_configured(Check):
    def execute(self):
        findings = []
        for distribution in cloudfront_client.distributions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = distribution.region
            report.resource_arn = distribution.arn
            report.resource_id = distribution.id
            report.resource_tags = distribution.tags
            report.status = "FAIL"
            report.status_extended = f"CloudFront Distribution {distribution.id} does not have an origin group configured with at least 2 origins."

            if distribution.origin_failover:
                report.status = "PASS"
                report.status_extended = f"CloudFront Distribution {distribution.id} has an origin group with at least 2 origins configured."

            findings.append(report)

        return findings
