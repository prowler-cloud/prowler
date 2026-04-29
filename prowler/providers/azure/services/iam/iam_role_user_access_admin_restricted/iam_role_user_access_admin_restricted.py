from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.iam.iam_client import iam_client


class iam_role_user_access_admin_restricted(Check):
    def execute(self):
        findings = []

        for subscription_id, assignments in iam_client.role_assignments.items():
            subscription_name = iam_client.subscriptions.get(
                subscription_id, subscription_id
            )
            for assignment in assignments.values():
                role_assignment_name = getattr(
                    iam_client.roles[subscription_id].get(
                        f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/{assignment.role_id}"
                    ),
                    "name",
                    "",
                )
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=assignment
                )
                report.subscription = subscription_id
                if role_assignment_name == "User Access Administrator":
                    report.status = "FAIL"
                    report.status_extended = f"Role assignment {assignment.name} in subscription {subscription_name} ({subscription_id}) grants User Access Administrator role to {getattr(assignment, 'agent_type', '')} {getattr(assignment, 'agent_id', '')}."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Role assignment {assignment.name} in subscription {subscription_name} ({subscription_id}) does not grant User Access Administrator role."
                findings.append(report)
        return findings
