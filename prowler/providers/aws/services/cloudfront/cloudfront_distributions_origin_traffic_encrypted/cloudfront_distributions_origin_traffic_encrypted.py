from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudfront.cloudfront_client import (
    cloudfront_client,
)


class cloudfront_distributions_origin_traffic_encrypted(Check):
    def execute(self):
        findings = []
        for distribution in cloudfront_client.distributions.values():
            report = Check_Report_AWS(
                metadata=self.metadata(), resource_metadata=distribution
            )
            report.status = "PASS"
            report.status_extended = f"CloudFront Distribution {distribution.id} does encrypt traffic to custom origins."
            unencrypted_origins = []

            for origin in distribution.origins:
                if (
                    origin.origin_protocol_policy == ""
                    or origin.origin_protocol_policy == "http-only"
                ) or (
                    origin.origin_protocol_policy == "match-viewer"
                    and distribution.viewer_protocol_policy == "allow-all"
                ):
                    unencrypted_origins.append(origin.id)

            if unencrypted_origins:
                report.status = "FAIL"
                report.status_extended = f"CloudFront Distribution {distribution.id} does not encrypt traffic to custom origins {', '.join(unencrypted_origins)}."

            findings.append(report)

        return findings
