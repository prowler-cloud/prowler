from typing import List

from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.entra.entra_client import entra_client


class entra_enterpriseapp_admin_consent_workflow_enabled(Check):
    """
    Ensure the admin consent workflow is enabled in Microsoft Entra.

    This check verifies that the admin consent workflow is enabled in Microsoft Entra to allow users
    to request admin approval for applications requiring consent. Enabling the admin consent workflow
    ensures that applications which require additional permissions are only granted access after an
    administrator’s approval, reducing the risk of unauthorized access and work disruptions.

    The check fails if the admin consent workflow is not enabled, indicating that users might be blocked
    from accessing critical applications or forced to use insecure workarounds.
    """

    def execute(self) -> List[CheckReportMicrosoft365]:
        """
        Execute the admin consent workflow requirement check.

        Retrieves the admin consent policy from the Microsoft Entra client and generates a report indicating
        whether the admin consent workflow is enabled.

        Returns:
            List[CheckReportMicrosoft365]: A list containing the report with the result of the check.
        """
        findings = []
        admin_consent_policy = entra_client.admin_consent_policy
        if admin_consent_policy:
            report = CheckReportMicrosoft365(
                self.metadata(),
                resource=admin_consent_policy,
                resource_name="Admin Consent Policy",
                resource_id=entra_client.tenant_domain,
            )
            report.status = "FAIL"
            report.status_extended = "The admin consent workflow is not enabled in Microsoft Entra; users may be blocked from accessing applications that require admin consent."
            if admin_consent_policy.admin_consent_enabled:
                report.status = "PASS"
                report.status_extended = "The admin consent workflow is enabled in Microsoft Entra, allowing users to request admin approval for applications."
                if admin_consent_policy.notify_reviewers:
                    report.status_extended += " Reviewers will be notified."
                else:
                    report.status_extended += (
                        " Reviewers will not be notified, we recommend notifying them."
                    )

            findings.append(report)
        return findings
