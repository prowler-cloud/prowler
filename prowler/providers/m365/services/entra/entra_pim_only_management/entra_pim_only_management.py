"""Check for role assignments made outside of Privileged Identity Management (PIM).

This check verifies that all privileged role assignments in Microsoft Entra ID
are managed through PIM, ensuring proper governance, audit trails, and
time-bound access controls for privileged roles.
"""

from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_pim_only_management(Check):
    """Ensure all privileged role assignments are managed through PIM.

    This check examines PIM alerts to detect role assignments that were made
    directly, bypassing Privileged Identity Management controls. Direct
    assignments circumvent governance safeguards such as approval workflows,
    justification requirements, and time-bound access.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the PIM-only management check.

        Iterates through PIM alerts looking for the RolesAssignedOutsidePimAlert
        type. If such an alert is active with affected items, the check fails.

        Returns:
            list[CheckReportM365]: A list containing a single finding, or an
                empty list if PIM alert data is not available.
        """
        findings = []

        if entra_client.pim_alerts is None:
            return findings

        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="PIM Alerts",
            resource_id="privilegedIdentityManagement",
        )
        report.status = "PASS"
        report.status_extended = "All privileged role assignments are managed through Privileged Identity Management (PIM)."

        for alert in entra_client.pim_alerts:
            if "RolesAssignedOutsidePimAlert" in alert.alert_definition_id:
                if alert.is_active and alert.number_of_affected_items > 0:
                    report.resource = alert.dict()
                    report.resource_id = alert.id
                    report.status = "FAIL"
                    report.status_extended = (
                        f"There are {alert.number_of_affected_items} privileged role"
                        f" assignment(s) made outside of PIM, bypassing governance controls."
                    )
                break

        findings.append(report)
        return findings
