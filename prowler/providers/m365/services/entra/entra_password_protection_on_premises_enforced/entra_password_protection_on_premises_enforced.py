from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    PASSWORD_RULE_SETTINGS_TEMPLATE_ID,
)


class entra_password_protection_on_premises_enforced(Check):
    """Check if Entra password protection is enforced on on-premises Active Directory.

    The Password Rule Settings directory setting should enable password protection on
    Windows Server Active Directory (EnableBannedPasswordCheckOnPremises) with the
    mode set to Enforced, so banned-password rules apply to hybrid on-premises
    password changes.

    - PASS: On-premises password protection is enabled and set to Enforced.
    - FAIL: On-premises password protection is disabled or set to Audit only.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the on-premises password protection enforcement check.

        Evaluate whether the Password Rule Settings directory setting enables and
        enforces banned-password protection for on-premises Active Directory. When the
        settings object is absent, no finding is produced.

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
            "On-premises password protection is not enforced in the tenant."
        )

        if settings:
            enabled = (
                str(settings.get("EnableBannedPasswordCheckOnPremises", "")).lower()
                == "true"
            )
            mode = str(settings.get("BannedPasswordCheckOnPremisesMode", "")).lower()
            if enabled and mode == "enforced":
                report.status = "PASS"
                report.status_extended = (
                    "On-premises password protection is enabled and enforced in the "
                    "tenant."
                )

        findings.append(report)
        return findings
