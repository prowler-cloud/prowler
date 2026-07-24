from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    PRIVILEGED_ROLE_ADMINISTRATOR_ROLE_TEMPLATE_ID,
)


class entra_pim_privileged_role_administrator_approval_required(Check):
    """Check if PIM requires approval to activate the Privileged Role Administrator role.

    Privileged Identity Management (PIM) should require approval to activate the
    Privileged Role Administrator role, with at least one approver configured.

    - PASS: Approval is required to activate Privileged Role Administrator and
      approvers exist.
    - FAIL: Approval is not required or no approvers are configured.
    """

    def execute(self) -> List[CheckReportM365]:
        """Evaluate PIM approval settings for the Privileged Role Administrator role.

        Reports whether Privileged Identity Management requires approval to activate
        the Privileged Role Administrator role and whether at least one approver is
        configured.

        Returns:
            List[CheckReportM365]: A single report for the Privileged Role
            Administrator PIM role settings, or an empty list when the settings are
            absent.
        """
        findings = []
        setting = entra_client.pim_role_approval_settings.get(
            PRIVILEGED_ROLE_ADMINISTRATOR_ROLE_TEMPLATE_ID
        )
        if not setting:
            return findings

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=setting,
            resource_name="Privileged Role Administrator PIM Role Settings",
            resource_id=PRIVILEGED_ROLE_ADMINISTRATOR_ROLE_TEMPLATE_ID,
        )
        report.status = "FAIL"
        report.status_extended = (
            "PIM does not require approval to activate the Privileged Role "
            "Administrator role."
        )

        if setting.is_approval_required and setting.has_approvers:
            report.status = "PASS"
            report.status_extended = (
                "PIM requires approval to activate the Privileged Role Administrator "
                "role and has approvers configured."
            )

        findings.append(report)
        return findings
