from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudfront.cloudfront_client import (
    cloudfront_client,
)
from prowler.providers.aws.services.cloudfront.cloudfront_service import (
    SSLSupportMethod,
)


class cloudfront_distributions_https_sni_enabled(Check):
    def execute(self):
        findings = []
        for distribution in cloudfront_client.distributions.values():
            if distribution.certificate:
                report = Check_Report_AWS(self.metadata(), distribution)

                if distribution.ssl_support_method == SSLSupportMethod.sni_only:
                    report.status = "PASS"
                    report.status_extended = f"CloudFront Distribution {distribution.id} is serving HTTPS requests using SNI."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"CloudFront Distribution {distribution.id} is not serving HTTPS requests using SNI."

                findings.append(report)

        return findings
