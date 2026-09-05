"""
policy_ensure_allowed_locations_is_enabled module.
"""

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.policy.policy_client import policy_client
from prowler.providers.azure.services.policy.policy_service import (
    check_policy_assignment_exists,
)


class policy_ensure_allowed_locations_is_enabled(Check):
    """Check if Allowed Locations policy is enabled.

    This check verifies if there is a policy assignment for the Allowed Locations built-in policy (e56962a6-4747-49cd-b67b-bf8b01975c4c).
    """

    def execute(self) -> list[Check_Report_Azure]:
        """Execute policy_ensure_allowed_locations_is_enabled check.

        Returns:
            list[Check_Report_Azure]: List of findings for subscriptions.
        """
        findings = []
        for subscription_id, assignments in policy_client.policy_assigments.items():
            report = Check_Report_Azure(
                metadata=self.metadata(),
                resource={},
            )
            report.subscription = subscription_id
            report.location = "global"
            report.resource_id = f"/subscriptions/{subscription_id}"
            report.resource_name = subscription_id

            if check_policy_assignment_exists(
                assignments, "e56962a6-4747-49cd-b67b-bf8b01975c4c"
            ):
                report.status = "PASS"
                report.status_extended = "Policy assignment for definition 'e56962a6-4747-49cd-b67b-bf8b01975c4c' exists with enforcement enabled."
            else:
                report.status = "FAIL"
                report.status_extended = "Policy assignment for definition 'e56962a6-4747-49cd-b67b-bf8b01975c4c' does not exist or enforcement is disabled."

            findings.append(report)

        return findings
