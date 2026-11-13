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
                    if _denies_insecure_transport_for_everyone(statement, bucket.arn):
                        report.status = "PASS"
                        report.status_extended = f"S3 Bucket {bucket.name} has a bucket policy to deny requests over insecure transport."
                        break

            findings.append(report)
        return findings


def _denies_insecure_transport_for_everyone(statement: dict, bucket_arn: str) -> bool:
    """Whether a bucket policy statement denies s3:PutObject over HTTP to every requester.

    The statement must be a Deny that applies to all principals and does not skip any
    object in the bucket with NotResource, its Action must cover s3:PutObject (or its
    NotAction must not) under IAM wildcard matching, and its only condition must be
    aws:SecureTransport being false. NotResource names the resources the deny skips,
    so HTTP stays allowed for any object it can match. Conditions are ANDed, so any other condition key narrows the
    deny and leaves HTTP allowed for requests outside it.

    Args:
        statement: A statement from the bucket policy.
        bucket_arn: The ARN of the bucket the policy is attached to.

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
    if any(
        _may_match_object_arn(not_resource, bucket_arn)
        for not_resource in not_resources
    ):
        return False

    if "NotAction" in statement:
        # NotAction denies every action except the ones it names
        not_actions = statement["NotAction"]
        if isinstance(not_actions, str):
            not_actions = [not_actions]
        if any(
            not isinstance(not_action, str)
            or iam_pattern_matches(not_action, "s3:PutObject")
            for not_action in not_actions
        ):
            return False
    else:
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


def _may_match_object_arn(resource: str, bucket_arn: str) -> bool:
    """Whether a resource ARN or pattern could match an object ARN in the bucket.

    A pattern can match some object ARN when one of its prefixes matches the object
    ARN prefix, since the rest of the pattern can then match the object key. Runs of
    "*" are collapsed first, which bounds the prefixes to try by the length of the
    object ARN prefix.

    Args:
        resource: A Resource or NotResource entry from the bucket policy.
        bucket_arn: The ARN of the bucket the policy is attached to.

    Returns:
        True when the entry could name an object in the bucket.
    """
    if not isinstance(resource, str):
        return True
    object_prefix = f"{bucket_arn}/"
    pattern = resource.strip()
    while "**" in pattern:
        pattern = pattern.replace("**", "*")
    longest_prefix = min(len(pattern), 2 * len(object_prefix) + 1)
    return any(
        iam_pattern_matches(pattern[:end], object_prefix)
        for end in range(longest_prefix + 1)
    )
