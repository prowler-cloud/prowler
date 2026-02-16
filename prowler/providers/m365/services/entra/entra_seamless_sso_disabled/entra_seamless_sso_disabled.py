from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_seamless_sso_disabled(Check):
    """Check that Seamless Single Sign-On (SSO) is disabled for Microsoft Entra hybrid deployments.

    Seamless SSO allows users to sign in without typing their passwords when on
    corporate devices connected to the corporate network. When an Entra Connect server
    is compromised, Seamless SSO can enable lateral movement between on-premises domains
    and Entra ID, and it can also be exploited for brute force attacks. Modern devices with
    Primary Refresh Token (PRT) support make this feature unnecessary for most organizations.

    - PASS: On-premises synchronization is not enabled, so Seamless SSO is not applicable.
    - FAIL: On-premises synchronization is enabled, indicating a hybrid deployment where
      Seamless SSO should be verified and disabled.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the Seamless SSO disabled check.

        Iterates over organizations to determine whether on-premises synchronization
        is enabled. Hybrid environments with on-premises sync enabled are flagged as
        requiring Seamless SSO to be disabled.

        Returns:
            A list of CheckReportM365 objects with the result of the check.
        """
        findings = []
        for organization in entra_client.organizations:
            report = CheckReportM365(
                self.metadata(),
                resource=organization,
                resource_id=organization.id,
                resource_name=organization.name,
            )
            report.status = "PASS"
            report.status_extended = f"Entra organization '{organization.name}' does not have on-premises sync enabled, Seamless SSO is not applicable."

            if organization.on_premises_sync_enabled:
                report.status = "FAIL"
                report.status_extended = f"Entra organization '{organization.name}' has on-premises sync enabled, Seamless SSO should be disabled to prevent lateral movement and brute force attacks."

            findings.append(report)
        return findings
