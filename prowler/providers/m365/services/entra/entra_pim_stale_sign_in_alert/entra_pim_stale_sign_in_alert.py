from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client

STALE_SIGN_IN_ALERT_DEFINITION_ID = "DirectoryRole_StaleSignInAlert"


class entra_pim_stale_sign_in_alert(Check):
    """Check if there are stale accounts in privileged roles detected by PIM.

    This check verifies that Privileged Identity Management (PIM) does not
    report any stale sign-in alerts for users with privileged role assignments.
    A stale account is one that has not signed in within a configured period
    (default 30 days) while still retaining a privileged directory role.

    Stale privileged accounts represent a significant security risk because
    unused credentials in elevated roles can be exploited by attackers without
    detection.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the PIM stale sign-in alert check.

        Retrieves the PIM stale sign-in alert from the Entra client and generates
        a report indicating whether stale accounts exist in privileged roles.

        Returns:
            List[CheckReportM365]: A list containing the report object with the result of the check.
        """
        findings = []

        stale_alert = entra_client.pim_alerts.get(STALE_SIGN_IN_ALERT_DEFINITION_ID)

        if stale_alert:
            report = CheckReportM365(
                self.metadata(),
                resource=stale_alert,
                resource_id=stale_alert.id,
                resource_name="PIM Stale Sign-In Alert",
            )

            if stale_alert.number_of_affected_items > 0:
                affected_users = ", ".join(
                    incident.assignee_display_name or incident.assignee_id
                    for incident in stale_alert.affected_items[:5]
                )
                suffix = (
                    f" and {stale_alert.number_of_affected_items - 5} more"
                    if stale_alert.number_of_affected_items > 5
                    else ""
                )
                report.status = "FAIL"
                report.status_extended = (
                    f"PIM detected {stale_alert.number_of_affected_items} "
                    f"stale account(s) in privileged roles: {affected_users}{suffix}."
                )
            else:
                report.status = "PASS"
                report.status_extended = "PIM stale sign-in alert reports no stale accounts in privileged roles."

            findings.append(report)
        else:
            for organization in entra_client.organizations:
                report = CheckReportM365(
                    self.metadata(),
                    resource=organization,
                    resource_id=organization.id,
                    resource_name=organization.name,
                )
                report.status = "FAIL"
                report.status_extended = "PIM stale sign-in alert is not configured or not available for the tenant."
                findings.append(report)

        return findings
