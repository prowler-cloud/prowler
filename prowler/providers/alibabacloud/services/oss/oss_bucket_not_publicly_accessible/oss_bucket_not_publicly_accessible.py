from prowler.lib.check.models import Check, CheckReportAlibabaCloud
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


class oss_bucket_not_publicly_accessible(Check):
    """Check if OSS bucket is not anonymously or publicly accessible."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        for bucket in oss_client.buckets.values():
            report = CheckReportAlibabaCloud(metadata=self.metadata(), resource=bucket)
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = bucket.arn

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
                    f"OSS bucket {bucket.name} is publicly accessible. "
                    + "; ".join(issues)
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"OSS bucket {bucket.name} is not publicly accessible. "
                    f"ACL is {bucket.acl} and bucket policy does not allow public access."
                )

            findings.append(report)

        return findings
