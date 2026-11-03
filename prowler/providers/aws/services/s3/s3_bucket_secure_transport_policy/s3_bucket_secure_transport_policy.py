from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import (
    has_public_principal,
    iam_pattern_matches,
)
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_secure_transport_policy(Check):
    def execute(self):
        findings = []
        for bucket in s3_client.buckets.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=bucket)
            # Check if bucket policy enforces SSL
            if not bucket.policy:
                report.status = "FAIL"
                report.status_extended = f"S3 Bucket {bucket.name} does not have a bucket policy, thus it allows HTTP requests."
            else:
                report.status = "FAIL"
                report.status_extended = f"S3 Bucket {bucket.name} allows requests over insecure transport in the bucket policy."
                statements = bucket.policy.get("Statement", [])
                if not isinstance(statements, list):
                    statements = [statements]
                for statement in statements:
                    if _denies_insecure_transport_for_everyone(statement):
                        report.status = "PASS"
                        report.status_extended = f"S3 Bucket {bucket.name} has a bucket policy to deny requests over insecure transport."
                        break

            findings.append(report)
        return findings


def _denies_insecure_transport_for_everyone(statement: dict) -> bool:
    """Whether a bucket policy statement denies s3:PutObject over HTTP to every requester.

    The statement must be a Deny that applies to all principals and does not skip any
    object with NotResource, its Action must cover s3:PutObject under IAM wildcard
    matching, and its only condition must be aws:SecureTransport being false.
    NotResource names the resources the deny skips, so HTTP stays allowed for any
    object it can match. Conditions are ANDed, so any other condition key narrows the
    deny and leaves HTTP allowed for requests outside it.

    Args:
        statement: A statement from the bucket policy.

    Returns:
        True when the statement enforces secure transport for every requester.
    """
    if not isinstance(statement, dict) or statement.get("Effect") != "Deny":
        return False
    if not has_public_principal(statement):
        return False
    not_resources = statement.get("NotResource", [])
    if isinstance(not_resources, str):
        not_resources = [not_resources]
    if any(_may_match_object_arn(not_resource) for not_resource in not_resources):
        return False

    actions = statement.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]
    if not any(
        isinstance(action, str) and iam_pattern_matches(action, "s3:PutObject")
        for action in actions
    ):
        return False

    condition = statement.get("Condition", {})
    if not isinstance(condition, dict) or list(condition) != ["Bool"]:
        return False
    bool_condition = condition["Bool"]
    # Condition key names are case-insensitive in IAM
    if not isinstance(bool_condition, dict) or [
        key.lower() for key in bool_condition
    ] != ["aws:securetransport"]:
        return False

    values = next(iter(bool_condition.values()))
    if not isinstance(values, list):
        values = [values]
    # Values of a single condition key are ORed, and AWS accepts both "false" and false
    return any(str(value).lower() == "false" for value in values)


def _may_match_object_arn(resource: str) -> bool:
    """Whether a resource ARN or pattern could match an S3 object ARN.

    Object ARNs always contain a "/" after the bucket name, and IAM wildcards also
    match "/", so only a literal ARN without "/" (such as the bucket ARN) is safe.

    Args:
        resource: A Resource or NotResource entry from the bucket policy.

    Returns:
        True unless the entry is a literal ARN that cannot name an object.
    """
    return not isinstance(resource, str) or any(char in resource for char in "/*?")
