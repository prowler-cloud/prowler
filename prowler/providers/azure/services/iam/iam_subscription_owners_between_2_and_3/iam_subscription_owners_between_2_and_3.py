from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.config import OWNER_ROLE_ID
from prowler.providers.azure.services.iam.iam_client import iam_client

MIN_OWNERS = 2
MAX_OWNERS = 3


class iam_subscription_owners_between_2_and_3(Check):
    """Subscription has between 2 and 3 principals with the Owner role."""

    def execute(self) -> list[Check_Report_Azure]:
        """Count the principals that hold the Owner role on each subscription.

        Owners assigned on the subscription and owners inherited from a
        management group or the root scope all count, once per principal.

        Returns:
            One finding per subscription. MANUAL when no role assignments
            could be read for the subscription.
        """
        findings = []
        for subscription_id, assignments in iam_client.role_assignments.items():
            subscription_name = iam_client.subscriptions.get(
                subscription_id, subscription_id
            )
            report = Check_Report_Azure(metadata=self.metadata(), resource={})
            report.subscription = subscription_id
            report.resource_name = subscription_id
            report.resource_id = f"/subscriptions/{subscription_id}"

            if not assignments:
                report.status = "MANUAL"
                report.status_extended = f"Role assignments for subscription {subscription_name} ({subscription_id}) could not be read; grant Microsoft.Authorization/roleAssignments/read (included in Reader) to count its owners."
                findings.append(report)
                continue

            subscription_scope = f"/subscriptions/{subscription_id}".lower()
            owner_assignments = [
                assignment
                for assignment in assignments.values()
                if assignment.role_id == OWNER_ROLE_ID
            ]
            owners = {assignment.agent_id for assignment in owner_assignments}
            direct_owners = {
                assignment.agent_id
                for assignment in owner_assignments
                if (assignment.scope or "").lower() == subscription_scope
            }
            owner_count = len(owners)
            inherited_count = len(owners - direct_owners)
            breakdown = f"{len(direct_owners)} direct, {inherited_count} inherited"

            if MIN_OWNERS <= owner_count <= MAX_OWNERS:
                report.status = "PASS"
                report.status_extended = f"Subscription {subscription_name} ({subscription_id}) has an owner count of {owner_count} ({breakdown}), within the recommended {MIN_OWNERS} to {MAX_OWNERS}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Subscription {subscription_name} ({subscription_id}) has an owner count of {owner_count} ({breakdown}), outside the recommended {MIN_OWNERS} to {MAX_OWNERS}."
            findings.append(report)
        return findings
