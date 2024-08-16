from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_cross_region_replication(Check):
    def execute(self):
        findings = []
        for arn, bucket in s3_client.buckets.items():
            report = Check_Report_AWS(self.metadata())
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = arn
            report.resource_tags = bucket.tags

            if (
                bucket.versioning
                and bucket.replication
                and bucket.replication.status == "Enabled"
                and bucket.replication.destination
            ):
                destination_bucket = s3_client.buckets.get(
                    bucket.replication.destination
                )
                if (
                    s3_client.buckets[bucket.replication.destination].region
                    != bucket.region
                ):
                    report.status = "PASS"
                    report.status_extended = f"S3 Bucket {bucket.name} has cross region replication in bucket {destination_bucket.name} located in region {destination_bucket.region}."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"S3 Bucket {bucket.name} does not have correct cross region replication configuration."
            else:
                report.status = "FAIL"
                report.status_extended = f"S3 Bucket {bucket.name} does not have correct cross region replication configuration."

            findings.append(report)

        return findings
