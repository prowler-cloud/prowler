from typing import List

from prowler.lib.check.models import Check, Check_Report_Microsoft365
from prowler.providers.microsoft365.services.entra.entra_client import entra_client


class entra_security_defaults_disabled(Check):
    """Check if Entra Security Defaults are disabled.

    This check verifies if the Entra Security Defaults are disabled in the Microsoft 365 environment.
    The check passes if security defaults are disabled, and fails if they are enabled.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[Check_Report_Microsoft365]:
        """Execute the Entra Security Defaults disabled check.

        This method checks the status of Entra Security Defaults and generates a report indicating
        whether security defaults are disabled or not.

        Returns:
            List[Check_Report_Microsoft365]: A list containing the report of the check, indicating
            whether the security defaults are disabled or enabled.
        """
        findings = []
        report = Check_Report_Microsoft365(
            metadata=self.metadata(), resource=entra_client.security_defaults
        )
        report.status = "FAIL"
        report.status_extended = "Entra Security Defaults is not disabled."

        if (
            entra_client.security_defaults is not None
            and not entra_client.security_defaults.is_enabled
        ):
            report.status = "PASS"
            report.status_extended = "Entra Security Defaults is disabled."

        findings.append(report)
        return findings
