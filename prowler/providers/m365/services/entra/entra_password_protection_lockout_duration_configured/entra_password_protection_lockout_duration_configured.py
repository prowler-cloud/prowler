from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    PASSWORD_RULE_SETTINGS_TEMPLATE_ID,
)

# CIS recommends a lockout duration of 60 seconds or more.
MIN_LOCKOUT_DURATION_SECONDS = 60


class entra_password_protection_lockout_duration_configured(Check):
    """Check if the smart lockout duration is set to 60 seconds or more.

    The Password Rule Settings directory setting should set LockoutDurationInSeconds
    to 60 or more so a locked-out account remains locked long enough to slow down
    automated attacks.

    - PASS: The lockout duration is 60 seconds or more.
    - FAIL: The lockout duration is less than 60 seconds or not configured.
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
        report.status_extended = (
            "The smart lockout duration is not set to 60 seconds or more."
        )

        if settings:
            try:
                duration = int(settings.get("LockoutDurationInSeconds"))
            except (TypeError, ValueError):
                duration = None
            if duration is not None and duration >= MIN_LOCKOUT_DURATION_SECONDS:
                report.status = "PASS"
                report.status_extended = (
                    f"The smart lockout duration is set to {duration} seconds, at or "
                    f"above the recommended minimum of {MIN_LOCKOUT_DURATION_SECONDS}."
                )

        findings.append(report)
        return findings
