from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    GROUP_UNIFIED_SETTINGS_TEMPLATE_ID,
)


class entra_policy_default_user_cannot_create_m365_groups(Check):
    """Check if default users are restricted from creating Microsoft 365 groups.

    The Group.Unified directory setting should have EnableGroupCreation set to false
    so that non-admin users cannot create Microsoft 365 groups. If the setting does
    not exist, the tenant uses the default, which allows all users to create groups.

    - PASS: Non-admin users cannot create Microsoft 365 groups.
    - FAIL: Non-admin users are allowed to create Microsoft 365 groups.
    """

    def execute(self) -> List[CheckReportM365]:
        findings = []
        settings = entra_client.directory_settings.get(
            GROUP_UNIFIED_SETTINGS_TEMPLATE_ID
        )

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=settings or {},
            resource_name="Group.Unified Settings",
            resource_id=GROUP_UNIFIED_SETTINGS_TEMPLATE_ID,
        )
        report.status = "FAIL"
        report.status_extended = (
            "Non-admin users are allowed to create Microsoft 365 groups."
        )

        if settings and str(settings.get("EnableGroupCreation", "")).lower() == "false":
            report.status = "PASS"
            report.status_extended = (
                "Non-admin users are not allowed to create Microsoft 365 groups."
            )

        findings.append(report)
        return findings
