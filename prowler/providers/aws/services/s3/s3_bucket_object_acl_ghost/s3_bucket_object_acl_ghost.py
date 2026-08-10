from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client

# Same URIs that make an object effectively public
PUBLIC_ACL_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


class s3_bucket_object_acl_ghost(Check):
    """Check for ghost public object ACLs when bucket enforces BucketOwnerEnforced."""

    def execute(self) -> List[Check_Report_AWS]:
        findings = []

        for bucket in s3_client.buckets.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=bucket)
            report.resource_id = bucket.name
            report.resource_arn = bucket.arn

            is_enforced = bucket.ownership and "BucketOwnerEnforced" in bucket.ownership

            if not is_enforced:
                report.status = "PASS"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} does not have BucketOwnerEnforced, "
                    f"ghost ACL check not applicable. Use s3_bucket_acl_prohibited and s3_bucket_object_public."
                )
                findings.append(report)
                continue

            sampling = bucket.object_sampling
            if sampling is None or not sampling.performed:
                report.status = "MANUAL"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} has BucketOwnerEnforced enabled but object ACL sampling was not performed, "
                    f"so ghost ACLs could not be evaluated. Enable s3_bucket_object_public_enabled in the audit configuration."
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
                    f"Could not evaluate ghost ACLs for bucket {bucket.name}: {sampling.error_message}."
                )
                findings.append(report)
                continue

            ghost_public_objects = [
                obj.key
                for obj in sampling.objects
                if any(
                    grantee.type == "Group" and grantee.URI in PUBLIC_ACL_URIS
                    for grantee in obj.grantees
                )
            ]

            if ghost_public_objects:
                sampled = len(sampling.objects)
                report.status = "FAIL"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} has BucketOwnerEnforced but sample of {sampled} objects "
                    f"still contains ghost public ACL grants that would become active if ownership is downgraded: "
                    f"{', '.join(ghost_public_objects)}. These ACLs are ignored today but remain stored and create drift risk."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"S3 Bucket {bucket.name} has BucketOwnerEnforced and no ghost public ACLs found in sampled objects. "
                    f"ACL drift is clean."
                )

            findings.append(report)

        return findings
