from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudfront.cloudfront_client import (
    cloudfront_client,
)


class cloudfront_distributions_default_root_object(Check):
    def execute(self):
        findings = []
        for distribution in cloudfront_client.distributions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = distribution.region
            report.resource_arn = distribution.arn
            report.resource_id = distribution.id
            report.resource_tags = distribution.tags

            if distribution.default_root_object:
                report.status = "PASS"
                report.status_extended = f"CloudFront Distribution {distribution.id} does have a default root object ({distribution.default_root_object}) configured."
            else:
                report.status = "FAIL"
                report.status_extended = f"CloudFront Distribution {distribution.id} does not have a default root object configured."

            findings.append(report)

        return findings
