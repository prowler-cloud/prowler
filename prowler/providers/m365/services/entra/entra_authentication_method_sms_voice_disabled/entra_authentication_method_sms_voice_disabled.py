from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_authentication_method_sms_voice_disabled(Check):
    """
    Ensure that SMS and Voice authentication methods are disabled in Microsoft Entra.

    This check verifies that the tenant's authentication methods policy has both SMS and
    Voice methods disabled, as they are vulnerable to SIM-swapping, interception, and
    social engineering attacks. NIST SP 800-63B deprecates SMS as an out-of-band
    authenticator.

    - PASS: Both SMS and Voice authentication methods are disabled.
    - FAIL: SMS or Voice authentication methods are enabled.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the SMS and Voice authentication method check.

        Iterates over the authentication method configurations from the Entra client
        and checks whether the SMS and Voice methods are disabled.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        authentication_method_configurations = (
            entra_client.authentication_method_configurations
        )

        for method_id in ["sms", "voice"]:
            config = authentication_method_configurations.get(method_id)
            if config:
                method_display = "SMS" if method_id == "sms" else "Voice"
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=config,
                    resource_name=f"{method_display} Authentication Method",
                    resource_id=entra_client.tenant_domain,
                )
                report.status = "PASS"
                report.status_extended = f"{method_display} authentication method is disabled in the tenant."

                if config.state == "enabled":
                    report.status = "FAIL"
                    report.status_extended = f"{method_display} authentication method is enabled in the tenant."

                findings.append(report)

        return findings
