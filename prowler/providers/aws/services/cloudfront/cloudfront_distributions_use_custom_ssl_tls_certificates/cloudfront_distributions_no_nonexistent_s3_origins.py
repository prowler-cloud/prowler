from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudfront.cloudfront_client import (
    cloudfront_client,
)


class cloudfront_distributions_no_nonexistent_s3_origins(Check):
    def execute(self):
        findings = []
        for distribution in cloudfront_client.distributions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = distribution.region
            report.resource_arn = distribution.arn
            report.resource_id = distribution.id
            report.resource_tags = distribution.tags
            report.status = "PASS"
            report.status_extended = f"CloudFront Distribution {distribution.id} does not have nonexistent S3 origins."

            for origin in distribution.origins:
                if len(origin["DomainName"]) == 0:
                    report.status = "FAIL"
                    report.status_extended = f"CloudFront Distribution {distribution.id} has nonexistent S3 origins."
                    break

            findings.append(report)

        return findings
