from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_authentication_method_email_otp_disabled(Check):
    """
    Ensure that the Email One-Time Passcode (OTP) authentication method is disabled.

    This check verifies that the tenant's authentication methods policy has the Email OTP
    method disabled. Email OTP relies on the security of the mailbox, which is often a
    lower-assurance channel and is unsuitable as a primary or fallback MFA method.

    - PASS: Email OTP authentication method is disabled.
    - FAIL: Email OTP authentication method is enabled.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the Email OTP authentication method check.

        Returns:
            A list with a single report containing the result of the check.
        """
        findings = []
        configs = entra_client.authentication_method_configurations

        email_config = configs.get("Email")

        if email_config:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=email_config,
                resource_name="Email OTP Authentication Method",
                resource_id=entra_client.tenant_domain,
            )

            if email_config.state == "disabled":
                report.status = "PASS"
                report.status_extended = (
                    "Email OTP authentication method is disabled in the tenant."
                )
            elif email_config.state == "enabled":
                report.status = "FAIL"
                report.status_extended = (
                    "Email OTP authentication method is enabled in the tenant."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    "Email OTP authentication method state could not be determined; "
                    "treating as enabled/non-compliant."
                )

            findings.append(report)

        return findings
