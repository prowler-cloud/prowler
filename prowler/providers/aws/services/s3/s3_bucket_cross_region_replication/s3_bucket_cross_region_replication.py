from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_cross_region_replication(Check):
    """Ensure S3 buckets replicate to a bucket in a different region.

    - PASS: At least one enabled replication rule targets a bucket in another region.
    - FAIL: Versioning is disabled, no enabled rule exists, or every resolvable
      destination is in the same region.
    - MANUAL: The versioning or replication configuration could not be retrieved
      (missing permissions), or a destination bucket is outside the audited
      account/scope so its region cannot be determined.
    """

    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        for bucket in s3_client.buckets.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=bucket)

            if not bucket.versioning_retrieved or not bucket.replication_retrieved:
                report.status = "MANUAL"
                report.status_extended = f"Cannot evaluate cross region replication for S3 Bucket {bucket.name}: the versioning or replication configuration could not be retrieved. Verify that the scanning credentials are allowed to call s3:GetBucketVersioning and s3:GetReplicationConfiguration."
                findings.append(report)
                continue

            report.status = "FAIL"
            report.status_extended = f"S3 Bucket {bucket.name} does not have correct cross region replication configuration."
            unresolvable_report = None
            same_region_report = None
            if bucket.replication_rules:
                for rule in bucket.replication_rules:
                    if (
                        bucket.versioning
                        and rule.status == "Enabled"
                        and rule.destination
                    ):
                        if rule.destination not in s3_client.buckets:
                            unresolvable_report = f"S3 Bucket {bucket.name} has cross region replication rule {rule.id} in bucket {rule.destination.split(':')[-1]} which is out of Prowler's scope; verify manually that the destination bucket is in a different region."
                        else:
                            destination_bucket = s3_client.buckets[rule.destination]
                            if destination_bucket.region != bucket.region:
                                report.status = "PASS"
                                report.status_extended = f"S3 Bucket {bucket.name} has cross region replication rule {rule.id} in bucket {destination_bucket.name} located in region {destination_bucket.region}."
                                break
                            else:
                                same_region_report = f"S3 Bucket {bucket.name} has cross region replication rule {rule.id} in bucket {destination_bucket.name} located in the same region."
            # Precedence: PASS > MANUAL (unresolvable destination) > FAIL
            if report.status != "PASS":
                if unresolvable_report:
                    report.status = "MANUAL"
                    report.status_extended = unresolvable_report
                elif same_region_report:
                    report.status_extended = same_region_report
            findings.append(report)

        return findings
