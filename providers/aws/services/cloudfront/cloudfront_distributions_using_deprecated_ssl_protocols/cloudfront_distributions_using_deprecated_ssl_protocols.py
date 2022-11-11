from lib.check.models import Check, Check_Report
from providers.aws.services.cloudfront.cloudfront_client import cloudfront_client

SSLV3 = "SSLv3"


class cloudfront_distributions_using_deprecated_ssl_protocols(Check):
    def execute(self):
        findings = []
        for distribution in cloudfront_client.distributions.values():
            report = Check_Report(self.metadata)
            report.region = distribution.region
            report.resource_arn = distribution.arn
            report.resource_id = distribution.id
            report.status = "PASS"
            report.status_extended = f"CloudFront Distribution {distribution.id} is not using a deprecated SSL protocol"

            for origin in distribution.origins:
                if "CustomOriginConfig" in origin:
                    if (
                        SSLV3
                        in origin["CustomOriginConfig"]["OriginSslProtocols"]["Items"]
                    ):
                        report.status = "FAIL"
                        report.status_extended = f"CloudFront Distribution {distribution.id} is using a deprecated SSL protocol"

            findings.append(report)

        return findings
