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
            report.status = "FAIL"
            report.status_extended = f"S3 Bucket {bucket.name} does not have correct cross region replication configuration."
            if (
                bucket.versioning
                and bucket.replication
                and bucket.replication.status == "Enabled"
                and bucket.replication.destination
            ):
                if bucket.replication.destination not in s3_client.buckets:
                    report.status = "FAIL"
                    report.status_extended = f"S3 Bucket {bucket.name} has cross region replication in bucket {bucket.replication.destination} which is out of Prowler's scope."
                else:
                    destination_bucket = s3_client.buckets[
                        bucket.replication.destination
                    ]
                    if destination_bucket.region != bucket.region:
                        report.status = "PASS"
                        report.status_extended = f"S3 Bucket {bucket.name} has cross region replication in bucket {destination_bucket.name} located in region {destination_bucket.region}."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"S3 Bucket {bucket.name} has cross region replication in bucket {destination_bucket.name} located in the same region."

            findings.append(report)

        return findings
