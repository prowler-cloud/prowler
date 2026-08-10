"""S3 bucket ghost ACL detection.

Buckets with BucketOwnerEnforced ignore ACLs at evaluation time, but
legacy object ACLs still exist and become active if ownership is
downgraded. This check surfaces that drift risk without relying on
live GetObjectAcl calls, which are blocked under BucketOwnerEnforced.

Live sampling under BucketOwnerEnforced cannot determine ghost ACLs
because GetObjectAcl is blocked. Therefore any non-empty enforced
bucket requires manual review.
"""

from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_object_acl_ghost(Check):
    """Check for ghost public ACL risk under BucketOwnerEnforced.

    When a bucket enforces BucketOwnerEnforced, object ACLs are ignored.
    Drift remains if objects still carry public grants that would reactivate
    on downgrade. Live GetObjectAcl sampling is not valid under enforced
    ownership, so this check reports MANUAL for review rather than FAIL/PASS
    based on sampling.

    Attributes:
        None required beyond Check base class metadata.

    """

    def execute(self) -> List[Check_Report_AWS]:
        """Execute the ghost ACL check for all S3 buckets.

        Evaluates each bucket for ghost public ACL risk:
        - MANUAL if ownership lookup failed (ownership is None)
        - PASS if ownership is known and not BucketOwnerEnforced (not applicable)
        - MANUAL if object sampling was not performed or bucket has objects
        - PASS if bucket empty
        - MANUAL for any non-empty BucketOwnerEnforced bucket to require manual review
        - MANUAL if sampling error occurred

        Returns:
            List of Check_Report_AWS with PASS or MANUAL status.
        """
        findings = []

        for bucket in s3_client.buckets.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=bucket)
            report.resource_id = bucket.name
            report.resource_arn = bucket.arn

            # Ownership lookup failure: Bucket.ownership is Optional[str].
            # When None, we cannot confirm enforcement, so do not report PASS.
            if bucket.ownership is None:
                report.status = "MANUAL"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} ownership could not be determined, "
                    f"cannot evaluate ghost ACL risk. Check GetBucketOwnershipControls permission."
                )
                findings.append(report)
                continue

            is_enforced = "BucketOwnerEnforced" in bucket.ownership

            if not is_enforced:
                report.status = "PASS"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} does not have BucketOwnerEnforced, "
                    f"ghost ACL check not applicable. Use s3_bucket_acl_prohibited and s3_bucket_object_public."
                )
                findings.append(report)
                continue

            sampling = bucket.object_sampling

            # If sampling info missing or not performed, MANUAL
            if sampling is None or not sampling.performed:
                report.status = "MANUAL"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} has BucketOwnerEnforced enabled but object ACL sampling was not performed, "
                    f"so ghost ACLs could not be evaluated live. Manual review of stored object ACLs via S3 Inventory or S3 Control API is required."
                )
                findings.append(report)
                continue

            if sampling.is_empty:
                report.status = "PASS"
                report.status_extended = f"S3 Bucket {bucket.name} is empty, no ghost public ACLs."
                findings.append(report)
                continue

            if sampling.error_code is not None:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not evaluate ghost ACLs for bucket {bucket.name}: {sampling.error_message}. "
                    f"Manual review required."
                )
                findings.append(report)
                continue

            # Critical flaw fix: live GetObjectAcl sampling invalid under BucketOwnerEnforced.
            # Any non-empty enforced bucket requires manual review of stored ACLs.
            if is_enforced and not sampling.is_empty:
                sampled = len(sampling.objects) if hasattr(sampling, "objects") else 0
                report.status = "MANUAL"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} has BucketOwnerEnforced and contains {sampled} sampled objects. "
                    f"Live GetObjectAcl sampling is blocked under BucketOwnerEnforced, so ghost public ACLs cannot be evaluated live. "
                    f"Manually inventory stored object ACLs using S3 Inventory with Object ACL field or S3 Batch Operations Copy inventory, "
                    f"verify no grants to AllUsers or AuthenticatedUsers, and rewrite affected objects via S3 Copy or S3 Batch Operations without ACL headers to purge ghost grants."
                )
                findings.append(report)
                continue

            # Fallback – should not reach here, but keep PASS for clean empty case
            report.status = "PASS"
            report.status_extended = (
                f"S3 Bucket {bucket.name} has BucketOwnerEnforced and no objects to evaluate, no ghost drift risk."
            )
            findings.append(report)

        return findings
