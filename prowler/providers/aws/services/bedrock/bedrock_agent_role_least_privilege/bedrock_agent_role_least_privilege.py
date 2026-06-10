from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_agent_client import (
    bedrock_agent_client,
)
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.policy import check_admin_access
from prowler.providers.aws.services.iam.lib.privilege_escalation import (
    check_privilege_escalation,
)


class bedrock_agent_role_least_privilege(Check):
    def execute(self) -> list[Check_Report_AWS]:
        findings = []
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

            for policy in role.attached_policies:
                policy_arn = policy.get("PolicyArn", "")
                policy_name = policy.get("PolicyName")
                if policy_arn.startswith(
                    "arn:aws:iam::aws:policy/"
                ) and policy_arn.endswith("FullAccess"):
                    violations.append(
                        f"managed policy {policy_name} grants full access"
                    )
                    continue
                policy_obj = iam_client.policies.get(policy_arn)
                if policy_obj is None or not policy_obj.document:
                    continue
                document = policy_obj.document
                if check_admin_access(document):
                    violations.append(
                        f"managed policy {policy_name} grants administrative access"
                    )
                elif check_privilege_escalation(document):
                    violations.append(
                        f"managed policy {policy_name} allows privilege escalation"
                    )

            for inline_name in role.inline_policies:
                policy_obj = iam_client.policies.get(f"{role.arn}:policy/{inline_name}")
                if policy_obj is None or not policy_obj.document:
                    continue
                document = policy_obj.document
                if check_admin_access(document):
                    violations.append(
                        f"inline policy {inline_name} grants administrative access"
                    )
                elif check_privilege_escalation(document):
                    violations.append(
                        f"inline policy {inline_name} allows privilege escalation"
                    )

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
