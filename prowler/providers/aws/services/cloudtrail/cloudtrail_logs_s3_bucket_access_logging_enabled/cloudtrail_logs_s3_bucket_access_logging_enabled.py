from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)
from prowler.providers.aws.services.s3.s3_client import s3_client


class cloudtrail_logs_s3_bucket_access_logging_enabled(Check):
    def execute(self):
        findings = []
        for trail in cloudtrail_client.trails:
            if trail.name:
                trail_bucket = trail.s3_bucket
                report = Check_Report_AWS(self.metadata())
                report.region = trail.region
                report.resource_id = trail.name
                report.resource_arn = trail.arn
                report.status = "FAIL"
                if trail.is_multiregion:
                    report.status_extended = f"Multiregion Trail {trail.name} S3 bucket access logging is not enabled for bucket {trail_bucket}"
                else:
                    report.status_extended = f"Single region Trail {trail.name} S3 bucket access logging is not enabled for bucket {trail_bucket}"
                for bucket in s3_client.buckets:
                    if trail_bucket == bucket.name and bucket.logging:
                        report.status = "PASS"
                        if trail.is_multiregion:
                            report.status_extended = f"Multiregion trail {trail.name} S3 bucket access logging is enabled for bucket {trail_bucket}"
                        else:
                            report.status_extended = f"Single region trail {trail.name} S3 bucket access logging is enabled for bucket {trail_bucket}"

                findings.append(report)

        return findings
