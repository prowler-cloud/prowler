from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_device_registration_laps_enabled(Check):
    """Check if Microsoft Entra Local Administrator Password Solution (LAPS) is enabled.

    The device registration policy should enable LAPS so that the built-in local
    administrator password on Windows devices is securely managed and rotated.

    - PASS: LAPS is enabled.
    - FAIL: LAPS is disabled.
    """

    def execute(self) -> List[CheckReportM365]:
        findings = []
        policy = entra_client.device_registration_policy
        if not policy:
            return findings

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=policy,
            resource_name="Device Registration Policy",
            resource_id="deviceRegistrationPolicy",
        )
        report.status = "FAIL"
        report.status_extended = (
            "Microsoft Entra Local Administrator Password Solution (LAPS) is disabled."
        )

        if policy.local_admin_password_enabled:
            report.status = "PASS"
            report.status_extended = (
                "Microsoft Entra Local Administrator Password Solution (LAPS) is "
                "enabled."
            )

        findings.append(report)
        return findings
