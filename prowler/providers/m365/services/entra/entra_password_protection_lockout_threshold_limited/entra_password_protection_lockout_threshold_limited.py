from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    PASSWORD_RULE_SETTINGS_TEMPLATE_ID,
)

# CIS recommends a smart lockout threshold of 10 or less.
MAX_LOCKOUT_THRESHOLD = 10


class entra_password_protection_lockout_threshold_limited(Check):
    """Check if the smart lockout threshold is set to 10 or less.

    The Password Rule Settings directory setting should set LockoutThreshold to 10 or
    less so that accounts are locked after a small number of failed sign-in attempts.

    - PASS: The lockout threshold is 10 or less.
    - FAIL: The lockout threshold is greater than 10 or not configured.
    """

    def execute(self) -> List[CheckReportM365]:
        findings = []
        settings = entra_client.directory_settings.get(
            PASSWORD_RULE_SETTINGS_TEMPLATE_ID
        )

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=settings or {},
            resource_name="Password Rule Settings",
            resource_id=PASSWORD_RULE_SETTINGS_TEMPLATE_ID,
        )
        report.status = "FAIL"
        report.status_extended = "The smart lockout threshold is not set to 10 or less."

        if settings:
            try:
                threshold = int(settings.get("LockoutThreshold"))
            except (TypeError, ValueError):
                threshold = None
            if threshold is not None and threshold <= MAX_LOCKOUT_THRESHOLD:
                report.status = "PASS"
                report.status_extended = (
                    f"The smart lockout threshold is set to {threshold}, within the "
                    f"recommended limit of {MAX_LOCKOUT_THRESHOLD}."
                )

        findings.append(report)
        return findings
