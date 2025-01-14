from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudfront.cloudfront_client import (
    cloudfront_client,
)
from prowler.providers.aws.services.cloudfront.cloudfront_service import (
    ViewerProtocolPolicy,
)


class cloudfront_distributions_https_enabled(Check):
    def execute(self):
        findings = []
        for distribution in cloudfront_client.distributions.values():
            report = Check_Report_AWS(
                metadata=self.metadata(), resource_metadata=distribution
            )

            if (
                distribution.default_cache_config
                and distribution.default_cache_config.viewer_protocol_policy
                == ViewerProtocolPolicy.redirect_to_https
            ):
                report.status = "PASS"
                report.status_extended = (
                    f"CloudFront Distribution {distribution.id} has redirect to HTTPS."
                )
            elif (
                distribution.default_cache_config
                and distribution.default_cache_config.viewer_protocol_policy
                == ViewerProtocolPolicy.https_only
            ):
                report.status = "PASS"
                report.status_extended = (
                    f"CloudFront Distribution {distribution.id} has HTTPS only."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"CloudFront Distribution {distribution.id} viewers can use HTTP or HTTPS."

            findings.append(report)

        return findings
