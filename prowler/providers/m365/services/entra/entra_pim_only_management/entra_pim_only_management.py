"""Check for role assignments made outside of Privileged Identity Management (PIM)."""

from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client

# Substring match against alert_definition_id. Microsoft Graph PIM exposes this
# alert under names such as ``RolesAssignedOutsidePimAlertDefinition`` (v1.0)
# and ``DirectoryRole_<scope>_RolesAssignedOutsidePimAlert`` (legacy beta).
# Matching on the stable suffix keeps the check working regardless of which
# format the API returns for the tenant being scanned.
ROLES_ASSIGNED_OUTSIDE_PIM_ALERT_SUBSTRING = "RolesAssignedOutsidePim"


class entra_pim_only_management(Check):
    """Ensure all privileged role assignments are managed through PIM.

    PIM raises ``RolesAssignedOutsidePim`` when a privileged directory role is
    granted to a principal directly, bypassing PIM's approval workflows,
    justification requirements, and time-bound access. This check inspects the
    PIM alert feed to detect that condition.

    - PASS: The alert exists and reports no affected items.
    - FAIL: The alert is active and has one or more affected items.
    - MANUAL: PIM alerts are not available for the tenant (no Microsoft Entra
      ID P2 license, alert disabled, or insufficient permissions to read PIM).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the PIM-only management check.

        Returns:
            list[CheckReportM365]: One finding per tenant, or an empty list if
                no organization is exposed by the provider.
        """
        findings = []

        if not entra_client.organizations:
            return findings

        organization = entra_client.organizations[0]

        matching_alert = next(
            (
                alert
                for alert in entra_client.pim_alerts.values()
                if ROLES_ASSIGNED_OUTSIDE_PIM_ALERT_SUBSTRING
                in (alert.alert_definition_id or "")
            ),
            None,
        )

        if matching_alert is None:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=organization,
                resource_id=organization.id,
                resource_name=organization.name,
            )
            report.status = "MANUAL"
            report.status_extended = (
                "PIM 'roles assigned outside of PIM' alert is not available. "
                "This can happen when the tenant lacks Microsoft Entra ID P2, "
                "the alert is disabled, or the running credentials cannot read "
                "PIM alerts. Review the alert configuration in the Entra admin "
                "center under Identity Governance > Privileged Identity "
                "Management > Alerts."
            )
            findings.append(report)
            return findings

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=matching_alert,
            resource_id=matching_alert.id,
            resource_name="PIM Roles Assigned Outside Of PIM Alert",
        )

        if matching_alert.is_active and matching_alert.number_of_affected_items > 0:
            report.status = "FAIL"
            report.status_extended = (
                f"PIM detected {matching_alert.number_of_affected_items} "
                "privileged role assignment(s) made outside of PIM, bypassing "
                "governance controls."
            )
        else:
            report.status = "PASS"
            report.status_extended = (
                "All privileged role assignments are managed through "
                "Privileged Identity Management (PIM)."
            )

        findings.append(report)
        return findings
