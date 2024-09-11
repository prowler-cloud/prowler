from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudfront.cloudfront_client import (
    cloudfront_client,
)
from prowler.providers.aws.services.s3.s3_client import s3_client


class cloudfront_s3_origin_non_existent_bucket(Check):
    def execute(self):
        findings = []
        for distribution in cloudfront_client.distributions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = distribution.region
            report.resource_arn = distribution.arn
            report.resource_id = distribution.id
            report.resource_tags = distribution.tags

            for origin in distribution.origins:
                report.status = "FAIL"
                report.status_extended = f"CloudFront Distribution {distribution.id} has a non-existent bucket as S3 origin: {origin.domain_name} or it is out of Prowler's scope."
                for bucket in s3_client.buckets.values():
                    if (
                        origin.domain_name
                        == f"{bucket.name}.s3.{bucket.region}.amazonaws.com"
                    ):
                        report.status = "PASS"
                        report.status_extended = f"CloudFront Distribution {distribution.id} does not have non-existent buckets as S3 origins."
                        break
                if report.status == "FAIL":
                    break

            findings.append(report)

        return findings
