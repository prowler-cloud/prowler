from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.actiontrail.actiontrail_client import (
    actiontrail_client,
)
from prowler.providers.alibabacloud.services.oss.oss_client import oss_client


def _is_policy_public(policy_document: dict) -> bool:
    """
    Check if a bucket policy allows public access.

    A policy is considered public if it has a statement with:
    - Effect: "Allow"
    - Principal: ["*"] (or contains "*")
    - No Condition elements

    Args:
        policy_document: The parsed policy document as a dictionary.

    Returns:
        bool: True if policy allows public access, False otherwise.
    """
    if not policy_document:
        return False

    statements = policy_document.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        effect = statement.get("Effect", "")
        principal = statement.get("Principal", [])
        condition = statement.get("Condition")

        # If there's a condition, it's not truly public
        if condition:
            continue

        if effect == "Allow":
            # Check if Principal is "*" or contains "*"
            if isinstance(principal, list):
                if "*" in principal:
                    return True
            elif principal == "*":
                return True

    return False


class actiontrail_oss_bucket_not_publicly_accessible(Check):
    """Check if the OSS bucket used to store ActionTrail logs is not publicly accessible."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        # Get all ActionTrail trails
        for trail in actiontrail_client.trails.values():
            # Only check trails that have an OSS bucket configured
            if not trail.oss_bucket_name:
                continue

            # Find the OSS bucket used by this trail
            bucket = None
            for oss_bucket in oss_client.buckets.values():
                if oss_bucket.name == trail.oss_bucket_name:
                    bucket = oss_bucket
                    break

            # Create report for this trail's OSS bucket
            report = CheckReportAlibabaCloud(metadata=self.metadata(), resource=trail)
            report.region = trail.home_region
            report.resource_id = trail.oss_bucket_name
            report.resource_arn = (
                f"acs:oss::{actiontrail_client.audited_account}:{trail.oss_bucket_name}"
            )

            if not bucket:
                # Bucket not found in OSS service (might not have permissions or bucket doesn't exist)
                report.status = "MANUAL"
                report.status_extended = (
                    f"ActionTrail trail {trail.name} uses OSS bucket {trail.oss_bucket_name}, "
                    "but the bucket could not be found or accessed. Please verify the bucket exists "
                    "and that you have permissions to access it."
                )
                findings.append(report)
                continue

            # Check bucket ACL
            acl_public = False
            if bucket.acl and bucket.acl != "private":
                if bucket.acl in ["public-read", "public-read-write"]:
                    acl_public = True

            # Check bucket policy
            policy_public = _is_policy_public(bucket.policy)

            # Determine status
            if acl_public or policy_public:
                report.status = "FAIL"
                issues = []
                if acl_public:
                    issues.append(f"Bucket ACL is set to {bucket.acl}")
                if policy_public:
                    issues.append("Bucket policy allows public access (Principal: '*')")
                report.status_extended = (
                    f"OSS bucket {trail.oss_bucket_name} used by ActionTrail trail {trail.name} "
                    f"is publicly accessible. {'; '.join(issues)}. "
                    "ActionTrail logs contain sensitive information and should not be publicly accessible."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"OSS bucket {trail.oss_bucket_name} used by ActionTrail trail {trail.name} "
                    f"is not publicly accessible. ACL is {bucket.acl} and bucket policy does not allow public access."
                )

            findings.append(report)

        return findings
