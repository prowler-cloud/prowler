from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudfront.cloudfront_client import (
    cloudfront_client,
)
from prowler.providers.aws.services.shield.shield_client import shield_client


class shield_advanced_protection_in_cloudfront_distributions(Check):
    def execute(self):
        findings = []
        if shield_client.enabled:
            for distribution in cloudfront_client.distributions.values():
                report = Check_Report_AWS(self.metadata())
                report.region = shield_client.region
                report.resource_id = distribution.id
                report.resource_arn = distribution.arn
                report.status = "FAIL"
                report.status_extended = f"CloudFront distribution {distribution.id} is not protected by AWS Shield Advanced"

                for protection in shield_client.protections.values():
                    if distribution.arn == protection.resource_arn:
                        report.status = "PASS"
                        report.status_extended = f"CloudFront distribution {distribution.id} is protected by AWS Shield Advanced"
                        break

                findings.append(report)

        return findings
