from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudfront.cloudfront_client import (
    cloudfront_client,
)


class cloudfront_distributions_s3_origin_access_control(Check):
    def execute(self):
        findings = []
        for distribution in cloudfront_client.distributions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = distribution.region
            report.resource_arn = distribution.arn
            report.resource_id = distribution.id
            report.resource_tags = distribution.tags

            if any(origin.s3_origin_config for origin in distribution.origins):
                s3_buckets_with_no_oac = []
                report.status = "PASS"
                report.status_extended = f"CloudFront Distribution {distribution.id} is using origin access control (OAC) for S3 origins."

                for origin in distribution.origins:
                    if (
                        origin.s3_origin_config != {}
                        and origin.origin_access_control == ""
                    ):
                        s3_buckets_with_no_oac.append(origin.id)

                if s3_buckets_with_no_oac:
                    report.status = "FAIL"
                    report.status_extended = f"CloudFront Distribution {distribution.id} is not using origin access control (OAC) in S3 origins {', '.join(s3_buckets_with_no_oac)}."

                findings.append(report)

        return findings
