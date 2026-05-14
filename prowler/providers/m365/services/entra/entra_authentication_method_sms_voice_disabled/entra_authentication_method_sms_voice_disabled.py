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
    - FAIL: SMS and/or Voice authentication methods are enabled.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the SMS and Voice authentication method check.

        Evaluates the authentication method configurations from the Entra client
        and checks whether both SMS and Voice methods are disabled.

        Returns:
            A list with a single report containing the result of the check.
        """
        findings = []
        configs = entra_client.authentication_method_configurations

        sms_config = configs.get("Sms")
        voice_config = configs.get("Voice")

        if sms_config or voice_config:
            sms_enabled = sms_config and sms_config.state == "enabled"
            voice_enabled = voice_config and voice_config.state == "enabled"

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=sms_config or voice_config,
                resource_name="SMS and Voice Authentication Methods",
                resource_id=entra_client.tenant_domain,
            )

            if sms_enabled and voice_enabled:
                report.status = "FAIL"
                report.status_extended = (
                    "SMS and Voice authentication methods are enabled in the tenant."
                )
            elif sms_enabled:
                report.status = "FAIL"
                report.status_extended = (
                    "SMS authentication method is enabled in the tenant."
                )
            elif voice_enabled:
                report.status = "FAIL"
                report.status_extended = (
                    "Voice authentication method is enabled in the tenant."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    "SMS and Voice authentication methods are disabled in the tenant."
                )

            findings.append(report)

        return findings
