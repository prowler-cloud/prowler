from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_agent_client import (
    bedrock_agent_client,
)
from prowler.providers.aws.services.iam.iam_client import iam_client

FULL_ACCESS_MANAGED_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/AmazonBedrockFullAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
}

def _role_name_from_arn(arn: str) -> str:
    return arn.split("/")[-1]


def _policy_has_wildcard_resource(policy_document: dict) -> bool:
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        if "*" not in resources:
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            if action == "*" or ":" in action and action.split(":")[1] == "*":
                return True
    return False


class bedrock_agent_role_least_privilege(Check):
    def execute(self):
        findings = []

        for agent in bedrock_agent_client.agents.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=agent)

            if not agent.agent_resource_role_arn:
                report.status = "FAIL"
                report.status_extended = f"Bedrock Agent {agent.name} has no execution role configured."
                findings.append(report)
                continue

            role_name = _role_name_from_arn(agent.agent_resource_role_arn)
            violations = []

            role = iam_client.roles.get(role_name)
            if role:
                for policy in role.attached_policies:
                    if policy["PolicyArn"] in FULL_ACCESS_MANAGED_POLICIES:
                        violations.append(f"full-access managed policy attached: {policy['PolicyArn']}")

            if violations:
                report.status = "FAIL"
                report.status_extended = (
                    f"Bedrock Agent {agent.name} execution role {role_name} "
                    f"violates least privilege: {'; '.join(violations)}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Bedrock Agent {agent.name} execution role {role_name} "
                    f"follows least privilege principles."
                )

            findings.append(report)

        return findings