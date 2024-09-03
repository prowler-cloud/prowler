from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudfront.cloudfront_client import (
    cloudfront_client,
)


class cloudfront_distributions_use_origin_access_control(Check):
    def execute(self):
        findings = []
        for distribution in cloudfront_client.distributions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = distribution.region
            report.resource_arn = distribution.arn
            report.resource_id = distribution.id
            report.resource_tags = distribution.tags
            report.status = "FAIL"
            report.status_extended = f"CloudFront Distribution {distribution.id} is not using origin access control (OAC)."

            if distribution.origin_access_control:
                report.status = "PASS"
                report.status_extended = f"CloudFront Distribution {distribution.id} is using origin access control (OAC)."

            findings.append(report)

        return findings
