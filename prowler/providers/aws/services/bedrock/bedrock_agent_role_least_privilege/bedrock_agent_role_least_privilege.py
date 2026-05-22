from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_agent_client import (
    bedrock_agent_client,
)
from prowler.providers.aws.services.iam.iam_client import iam_client

# Broad action patterns that, combined with Resource:"*", indicate the role
# can do effectively anything in the targeted service. Kept conservative so
# narrow checks (e.g. "s3:GetObject" on "*") don't trip a FAIL.
BROAD_ACTION_PATTERNS = (
    "*",
    "iam:*",
    "s3:*",
    "ec2:*",
    "kms:*",
    "secretsmanager:*",
    "dynamodb:*",
    "lambda:*",
    "sts:*",
)


def _as_list(value):
    """Coerce a string or list field into a list (IAM policy docs accept either)."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


class bedrock_agent_role_least_privilege(Check):
    """Ensure Bedrock Agent execution roles follow least privilege.

    A permissive execution role turns a successful prompt-injection into AWS
    privilege escalation: the LLM can be tricked into calling whatever APIs
    the role allows. This check FAILs the role when any of the following
    are true:

    - An AWS-managed *FullAccess policy is attached.
    - An inline statement allows broad actions on Resource:"*".
    - No permissions boundary is configured.
    """

    def execute(self) -> list[Check_Report_AWS]:
        findings = []

        # Lookup table so we don't scan iam_client.roles per agent.
        roles_by_arn = {role.arn: role for role in (iam_client.roles or [])}

        for agent in bedrock_agent_client.agents.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=agent)
            report.status = "PASS"
            report.status_extended = (
                f"Bedrock Agent {agent.name} execution role follows least privilege."
            )

            role = roles_by_arn.get(agent.role_arn) if agent.role_arn else None
            if role is None:
                report.status = "FAIL"
                report.status_extended = (
                    f"Bedrock Agent {agent.name} execution role could not be "
                    f"resolved in IAM and cannot be evaluated for least privilege."
                )
                findings.append(report)
                continue

            violations = []

            # Criterion 1: no AWS-managed *FullAccess policies attached.
            for policy in role.attached_policies:
                policy_arn = policy.get("PolicyArn", "")
                if policy_arn.startswith("arn:aws:iam::aws:policy/") and policy_arn.endswith(
                    "FullAccess"
                ):
                    violations.append(
                        f"managed policy {policy.get('PolicyName')} grants full access"
                    )

            # Criterion 2: no inline statement with Resource:"*" + broad action.
            for inline_name in role.inline_policies:
                policy_obj = iam_client.policies.get(
                    f"{role.arn}:policy/{inline_name}"
                )
                if policy_obj is None or not policy_obj.document:
                    continue
                for statement in _as_list(policy_obj.document.get("Statement", [])):
                    if statement.get("Effect") != "Allow":
                        continue
                    resources = _as_list(statement.get("Resource"))
                    actions = _as_list(statement.get("Action"))
                    if "*" in resources and any(
                        action in BROAD_ACTION_PATTERNS for action in actions
                    ):
                        violations.append(
                            f"inline policy {inline_name} grants broad actions on Resource:*"
                        )
                        break  # one violation per policy is enough

            # Criterion 3: a permissions boundary is configured.
            if not role.permissions_boundary:
                violations.append("no permissions boundary configured")

            if violations:
                report.status = "FAIL"
                report.status_extended = (
                    f"Bedrock Agent {agent.name} execution role violates least "
                    f"privilege: {'; '.join(violations)}."
                )

            findings.append(report)

        return findings
