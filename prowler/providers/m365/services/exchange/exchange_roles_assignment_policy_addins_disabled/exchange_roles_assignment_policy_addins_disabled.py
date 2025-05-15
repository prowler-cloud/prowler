from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.exchange.exchange_client import exchange_client
from prowler.providers.m365.services.exchange.exchange_service import AddinRoles


class exchange_roles_assignment_policy_addins_disabled(Check):
    """Check if any Exchange role assignment policy allows Outlook add-ins.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for role assignment policies that allow Outlook add-ins.

        This method checks all Exchange Online Role Assignment Policies to verify
        whether any of them allow the installation of add-ins by including risky roles.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []

        addin_roles = [e.value for e in AddinRoles]

        for policy in exchange_client.role_assignment_policies:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.name,
                resource_id=policy.id,
            )

            report.status = "PASS"
            report.status_extended = f"Role assignment policy '{policy.name}' does not allow Outlook add-ins."

            risky_roles_found = []
            for role in policy.assigned_roles:
                if role in addin_roles:
                    risky_roles_found.append(role)

            if risky_roles_found:
                report.status = "FAIL"
                report.status_extended = f"Role assignment policy '{policy.name}' allows Outlook add-ins via roles: {', '.join(risky_roles_found)}."

            findings.append(report)

        return findings
