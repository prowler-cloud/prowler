from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client

# The alert definition ID for "Administrators aren't using their privileged roles"
# (also known as the StaleSignInAlert or inactive role assignment alert).
STALE_SIGN_IN_ALERT_DEFINITION_ID = "DirectoryRoleInactiveAlertDefinition"


class entra_pim_role_usage_alert_exists(Check):
    """
    Ensure that the PIM alert for unused privileged roles is configured and active.

    This check verifies that Privileged Identity Management (PIM) is configured
    to alert when administrators are not using their assigned privileged roles,
    helping detect stale or unnecessary role assignments.
    - PASS: The PIM alert for unused privileged roles exists and is active.
    - FAIL: The PIM alert for unused privileged roles does not exist or is not active.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="PIM Role Usage Alert",
            resource_id="pimRoleUsageAlert",
        )
        report.status = "FAIL"
        report.status_extended = "PIM alert for unused privileged roles does not exist or is not active."

        for alert in entra_client.pim_alerts:
            if (
                STALE_SIGN_IN_ALERT_DEFINITION_ID
                in alert.alert_definition_id
                and alert.is_active
            ):
                report.status = "PASS"
                report.status_extended = "PIM alert for unused privileged roles exists and is active."
                break

        findings.append(report)
        return findings
