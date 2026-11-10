from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.policy import iam_pattern_matches

PAYMENT_ACTIONS = (
    "bedrock-agentcore:CreatePaymentSession",
    "bedrock-agentcore:ProcessPayment",
)


def _patterns(value) -> list:
    """Normalise an Action, NotAction or Resource value to a list of strings."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _statements(document: dict) -> list:
    """Return a policy document's statements as a list of dicts."""
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []
    return [statement for statement in statements if isinstance(statement, dict)]


def _effect(statement: dict) -> str:
    return str(statement.get("Effect", "")).strip().lower()


def _names_action(statement: dict, action: str) -> bool:
    """Whether a statement's Action or NotAction covers the given action."""
    if "NotAction" in statement:
        return not any(
            iam_pattern_matches(pattern, action)
            for pattern in _patterns(statement["NotAction"])
        )
    return any(
        iam_pattern_matches(pattern, action)
        for pattern in _patterns(statement.get("Action"))
    )


def granted_payment_actions(statements: list) -> list:
    """Return the payment actions a role's aggregated statements still allow after Deny.

    Args:
        statements: Every statement from the role's attached and inline policies.

    Returns:
        The subset of PAYMENT_ACTIONS that is allowed and not unconditionally denied.
    """
    allows = [s for s in statements if _effect(s) == "allow"]
    # shortcut: only a Deny on Resource "*" with no Condition/NotResource is credited, so a
    # resource-scoped Deny or a split across payment managers still FAILs; resolve resource
    # ARNs if that turns out to produce false positives.
    denies = [
        s
        for s in statements
        if _effect(s) == "deny"
        and "Condition" not in s
        and "NotResource" not in s
        and "*" in _patterns(s.get("Resource"))
    ]
    return [
        action
        for action in PAYMENT_ACTIONS
        if any(_names_action(s, action) for s in allows)
        and not any(_names_action(s, action) for s in denies)
    ]


class bedrockagentcore_payments_process_payment_role_separation(Check):
    """Ensure no IAM role can both create and process Bedrock AgentCore payments.

    The role's attached and inline policies are evaluated together, so a Deny in one
    policy removes an Allow from another. Service roles and roles granting neither
    payment action are skipped.
    - PASS: The role allows only one of CreatePaymentSession and ProcessPayment.
    - FAIL: The role allows both actions.
    - MANUAL: The IAM roles could not be listed, or one of the role's policies could not be read.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        if iam_client.roles is None:
            report = Check_Report_AWS(metadata=self.metadata(), resource={})
            report.region = iam_client.region
            report.resource_id = iam_client.audited_account
            report.resource_arn = iam_client.role_arn_template
            report.status = "MANUAL"
            report.status_extended = (
                "IAM roles could not be listed, so this check could not be evaluated."
            )
            return [report]

        for role in iam_client.roles:
            if role.is_service_role:
                continue
            statements = []
            unresolved = []
            policies = [
                (policy.get("PolicyArn", ""), policy.get("PolicyName", ""))
                for policy in role.attached_policies
            ] + [(f"{role.arn}:policy/{name}", name) for name in role.inline_policies]
            for policy_arn, policy_name in policies:
                policy = iam_client.policies.get(policy_arn)
                if policy is None or not policy.document:
                    unresolved.append(policy_name or policy_arn)
                    continue
                statements.extend(_statements(policy.document))

            granted = granted_payment_actions(statements)
            if not granted and not unresolved:
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=role)
            report.region = iam_client.region
            if len(granted) == len(PAYMENT_ACTIONS):
                report.status = "FAIL"
                report.status_extended = f"IAM Role {role.name} allows both bedrock-agentcore:CreatePaymentSession and bedrock-agentcore:ProcessPayment."
            elif unresolved:
                report.status = "MANUAL"
                report.status_extended = f"IAM Role {role.name} has policies that could not be retrieved ({', '.join(sorted(unresolved))}), so it cannot be verified that it does not allow both bedrock-agentcore:CreatePaymentSession and bedrock-agentcore:ProcessPayment."
            else:
                report.status = "PASS"
                report.status_extended = f"IAM Role {role.name} allows {granted[0]} but not both payment actions."
            findings.append(report)
        return findings
