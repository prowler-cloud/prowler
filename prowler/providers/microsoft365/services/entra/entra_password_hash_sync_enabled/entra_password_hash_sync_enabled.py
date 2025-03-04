from typing import List

from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.entra.entra_client import entra_client


class entra_password_hash_sync_enabled(Check):
    """
    Check if password hash synchronization is enabled for hybrid Microsoft Entra deployments.

    This check verifies that password hash synchronization is enabled in hybrid Microsoft Entra deployments.
    Enabling password hash sync ensures that on-premises passwords are synchronized to Microsoft Entra,
    facilitating seamless authentication and enhancing leaked credential protection. Without password hash
    synchronization, users might have to manage multiple passwords and detection of leaked credentials would be compromised.

    Note: This control applies only to hybrid deployments using Microsoft Entra Connect sync and does not apply to federated domains.
    """

    def execute(self) -> List[CheckReportMicrosoft365]:
        """
        Execute the password hash synchronization requirement check.

        Retrieves the organization settings from the Entra client and generates a report indicating whether
        password hash synchronization is enabled.

        Returns:
            List[CheckReportMicrosoft365]: A list containing the report object with the result of the check.
        """
        findings = []
        for organization in entra_client.organizations:
            report = CheckReportMicrosoft365(
                self.metadata(),
                resource=organization,
                resource_id=organization.id,
                resource_name=organization.name,
            )
            report.status = "FAIL"
            report.status_extended = "Password hash synchronization is not enabled for hybrid Microsoft Entra deployments."

            if organization.on_premises_sync_enabled:
                report.status = "PASS"
                report.status_extended = "Password hash synchronization is enabled for hybrid Microsoft Entra deployments."

            findings.append(report)
        return findings
