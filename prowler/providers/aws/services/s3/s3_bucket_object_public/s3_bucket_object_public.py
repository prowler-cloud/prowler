from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client

# ACL grantee groups that make an object effectively public. AllUsers is anyone on
# the internet; AuthenticatedUsers is any authenticated AWS principal (any account).
PUBLIC_ACL_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


class s3_bucket_object_public(Check):
    """Spot-check a sample of S3 bucket objects for public ACL grants."""

    def execute(self) -> List[Check_Report_AWS]:
        """Evaluate sampled object ACLs for AllUsers/AuthenticatedUsers grants.

        Returns:
            List[Check_Report_AWS]: One report per sampled bucket (empty when the
            check is disabled via configuration).
        """
        findings = []

        if not s3_client.audit_config.get("s3_bucket_object_public_enabled", False):
            return findings

        for bucket in s3_client.buckets.values():
            sampling = bucket.object_sampling
            # Sampling is populated by the service layer only when the check is
            # enabled; skip any bucket that was not sampled.
            if sampling is None or not sampling.performed:
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=bucket)

            if sampling.error_code is not None:
                report.status = "MANUAL"
                if sampling.error_code == "AccessDenied":
                    report.status_extended = (
                        f"Access Denied when spot-checking objects in bucket "
                        f"{bucket.name}."
                    )
                else:
                    report.status_extended = (
                        f"Could not spot-check objects in bucket {bucket.name}: "
                        f"{sampling.error_message}."
                    )
            elif sampling.is_empty:
                report.status = "PASS"
                report.status_extended = f"S3 Bucket {bucket.name} is empty."
            else:
                public_objects = [
                    obj.key
                    for obj in sampling.objects
                    if any(
                        grantee.type == "Group" and grantee.URI in PUBLIC_ACL_URIS
                        for grantee in obj.grantees
                    )
                ]
                sampled = len(sampling.objects)

                if public_objects:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"S3 Bucket {bucket.name} has public objects detected in "
                        f"spot-check sample of {sampled} objects: "
                        f"{', '.join(public_objects)}."
                    )
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"No public objects detected in spot-check sample of "
                        f"{sampled} objects in bucket {bucket.name}. For complete "
                        f"assurance, ensure ACLs are disabled via Object Ownership "
                        f"settings."
                    )

            findings.append(report)

        return findings
