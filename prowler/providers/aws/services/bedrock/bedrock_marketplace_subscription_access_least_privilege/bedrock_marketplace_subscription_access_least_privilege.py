from fnmatch import fnmatch

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client

TARGET_ACTION = "aws-marketplace:subscribe"


def _policy_allows_marketplace_subscribe_on_all_resources(
    policy_document: dict,
) -> bool:
    """Check if a policy document allows aws-marketplace:Subscribe on Resource:*.

    Inspects each statement in the policy document for Allow statements that
    grant the ``aws-marketplace:Subscribe`` action (or a wildcard pattern that
    matches it) on all resources (``*``).  Explicit Deny statements for the
    same action take precedence and negate the finding.

    Args:
        policy_document: The IAM policy document to analyse.

    Returns:
        True if the policy effectively allows aws-marketplace:Subscribe on
        all resources, False otherwise.
    """
    if not policy_document or "Statement" not in policy_document:
        return False

    statements = policy_document.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    is_allowed = False
    is_denied = False

    for statement in statements:
        effect = statement.get("Effect", "")
        if not isinstance(effect, str):
            continue

        resources = statement.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]

        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        action_matches = any(
            fnmatch(TARGET_ACTION, action.lower()) for action in actions
        )

        if not action_matches:
            continue

        if effect == "Allow" and "*" in resources:
            is_allowed = True
        elif effect == "Deny" and "*" in resources:
            is_denied = True

    return is_allowed and not is_denied


class bedrock_marketplace_subscription_access_least_privilege(Check):
    """Ensure IAM policies restrict aws-marketplace:Subscribe to specific resources.

    This check evaluates custom IAM policies for overly broad
    ``aws-marketplace:Subscribe`` permissions granted on all resources (``*``).
    Unrestricted subscribe access allows principals to subscribe to any AWS
    Marketplace product, including Amazon Bedrock foundation models, without
    governance controls.

    - PASS: The policy does not allow aws-marketplace:Subscribe on all resources.
    - FAIL: The policy allows aws-marketplace:Subscribe on all resources.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        for policy in iam_client.policies.values():
            if policy.type == "Custom":
                report = Check_Report_AWS(metadata=self.metadata(), resource=policy)
                report.region = iam_client.region
                report.status = "PASS"
                report.status_extended = f"IAM policy {policy.name} does not allow aws-marketplace:Subscribe on all resources."

                if (
                    policy.document
                    and _policy_allows_marketplace_subscribe_on_all_resources(
                        policy.document
                    )
                ):
                    report.status = "FAIL"
                    report.status_extended = f"IAM policy {policy.name} allows aws-marketplace:Subscribe on all resources."

                findings.append(report)
        return findings
