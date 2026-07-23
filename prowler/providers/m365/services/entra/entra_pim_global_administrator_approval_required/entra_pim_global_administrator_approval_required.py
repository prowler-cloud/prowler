from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    GLOBAL_ADMINISTRATOR_ROLE_TEMPLATE_ID,
)


class entra_pim_global_administrator_approval_required(Check):
    """Check if PIM requires approval to activate the Global Administrator role.

    Privileged Identity Management (PIM) should require approval to activate the
    Global Administrator role, with at least one approver configured.

    - PASS: Approval is required to activate Global Administrator and approvers exist.
    - FAIL: Approval is not required, no approvers are configured, or PIM settings are
      unavailable.
    """

    def execute(self) -> List[CheckReportM365]:
        findings = []
        setting = entra_client.pim_role_approval_settings.get(
            GLOBAL_ADMINISTRATOR_ROLE_TEMPLATE_ID
        )
        if not setting:
            return findings

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=setting,
            resource_name="Global Administrator PIM Role Settings",
            resource_id=GLOBAL_ADMINISTRATOR_ROLE_TEMPLATE_ID,
        )
        report.status = "FAIL"
        report.status_extended = (
            "PIM does not require approval to activate the Global Administrator role."
        )

        if setting.is_approval_required and setting.has_approvers:
            report.status = "PASS"
            report.status_extended = (
                "PIM requires approval to activate the Global Administrator role and "
                "has approvers configured."
            )

        findings.append(report)
        return findings
