from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudfront.cloudfront_client import (
    cloudfront_client,
)


class cloudfront_distributions_origin_failover_enabled(Check):
    def execute(self):
        findings = []
        for distribution in cloudfront_client.distributions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = distribution.region
            report.resource_arn = distribution.arn
            report.resource_id = distribution.id
            report.resource_tags = distribution.tags
            report.status = "FAIL"
            report.status_extended = f"CloudFront Distribution {distribution.id} does not have an origin group with two or more origins."

            for origin_group in distribution.origins:
                if len(origin_group["Items"]) >= 2:
                    report.status = "PASS"
                    report.status_extended = f"CloudFront Distribution {distribution.id} has an origin group with two or more origins."
                    break

            findings.append(report)

        return findings
