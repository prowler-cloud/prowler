from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    PASSWORD_RULE_SETTINGS_TEMPLATE_ID,
)


class entra_password_protection_custom_banned_list_enforced(Check):
    """Check if the Entra custom banned password list is enforced.

    The Password Rule Settings directory setting should enforce a custom banned
    password list (EnableBannedPasswordCheck) with a non-empty BannedPasswordList so
    that organization-specific weak passwords are rejected in addition to the global
    banned list.

    - PASS: The custom banned password list is enforced and non-empty.
    - FAIL: The custom banned password list is not enforced or is empty.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the custom banned password list enforcement check.

        Evaluate whether the Password Rule Settings directory setting enforces a
        non-empty custom banned password list. When the settings object is absent,
        no finding is produced.

        Returns:
            List[CheckReportM365]: A list with a single report when the Password Rule
            Settings exist, or an empty list when they are absent.
        """
        findings = []
        settings = entra_client.directory_settings.get(
            PASSWORD_RULE_SETTINGS_TEMPLATE_ID
        )
        if not settings:
            return findings

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=settings or {},
            resource_name="Password Rule Settings",
            resource_id=PASSWORD_RULE_SETTINGS_TEMPLATE_ID,
        )
        report.status = "FAIL"
        report.status_extended = (
            "The custom banned password list is not enforced in the tenant."
        )

        if settings:
            enforced = (
                str(settings.get("EnableBannedPasswordCheck", "")).lower() == "true"
            )
            banned_list = settings.get("BannedPasswordList", "") or ""
            if enforced and banned_list.strip():
                report.status = "PASS"
                report.status_extended = (
                    "The custom banned password list is enforced in the tenant."
                )

        findings.append(report)
        return findings
