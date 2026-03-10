from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.ram.ram_client import ram_client


def check_admin_access(policy_document: dict) -> bool:
    """
    Check if the policy document allows full administrative privileges.

    Args:
        policy_document: The policy document as a dictionary.

    Returns:
        bool: True if the policy allows admin access (Effect: Allow, Action: *, Resource: *), False otherwise.
    """
    if not policy_document:
        return False

    statements = policy_document.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        effect = statement.get("Effect")
        action = statement.get("Action")
        resource = statement.get("Resource")

        # Check if statement has Effect: Allow, Action: *, Resource: *
        if effect == "Allow":
            # Action can be a string or a list
            actions = action if isinstance(action, list) else [action] if action else []
            # Resource can be a string or a list
            resources = (
                resource
                if isinstance(resource, list)
                else [resource] if resource else []
            )

            # Check if Action contains "*" and Resource contains "*"
            if "*" in actions and "*" in resources:
                return True

    return False


class ram_policy_no_administrative_privileges(Check):
    """Check if RAM policies that allow full '*:*' administrative privileges are not created."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        for policy in ram_client.policies.values():
            # Check only for custom policies that are attached
            if policy.policy_type == "Custom" and policy.attachment_count > 0:
                report = CheckReportAlibabaCloud(
                    metadata=self.metadata(), resource=policy
                )
                report.region = ram_client.region
                report.resource_id = policy.name
                report.resource_arn = (
                    f"acs:ram::{ram_client.audited_account}:policy/{policy.name}"
                )

                report.status = "PASS"
                report.status_extended = f"Custom policy {policy.name} is attached but does not allow '*:*' administrative privileges."

                if policy.document:
                    if check_admin_access(policy.document):
                        report.status = "FAIL"
                        report.status_extended = f"Custom policy {policy.name} is attached and allows '*:*' administrative privileges."

                findings.append(report)

        return findings
