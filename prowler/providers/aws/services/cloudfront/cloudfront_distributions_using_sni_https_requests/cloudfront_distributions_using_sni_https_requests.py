from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudfront.cloudfront_client import (
    cloudfront_client,
)


class cloudfront_distributions_using_sni_https_requests(Check):
    def execute(self):
        findings = []
        for distribution in cloudfront_client.distributions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = distribution.region
            report.resource_arn = distribution.arn
            report.resource_id = distribution.id
            report.resource_tags = distribution.tags
            report.status = "FAIL"
            report.status_extended = f"CloudFront Distribution {distribution.id} does not have a certificate."

            if distribution.certificate:
                if distribution.ssl_support_method == "sni-only":
                    report.status = "PASS"
                    report.status_extended = f"CloudFront Distribution {distribution.id} has configured certificate to serve HTTPS requests with SNI."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"CloudFront Distribution {distribution.id} does have a certificate but is not set up to use SNI."
            findings.append(report)

        return findings
