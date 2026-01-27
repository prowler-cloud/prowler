from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_default_app_management_policy_enabled(Check):
    """
    Check if the default app management policy is enabled in Microsoft Entra.

    This check verifies that the tenant-wide default app management policy is enabled
    to enforce credential configurations on applications and service principals.
    By default, Microsoft Entra ID allows service principals and applications to be
    created without credentials, which can pose security risks.

    When the default app management policy is enabled, administrators can enforce
    restrictions on password credentials and key credentials for applications,
    helping to improve the security posture of the tenant.
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the default app management policy check.

        Retrieves the default app management policy from the Microsoft Entra client
        and generates a report indicating whether the policy is enabled.

        Returns:
            List[CheckReportM365]: A list containing the report with the result of the check.
        """
        findings = []
        default_app_management_policy = entra_client.default_app_management_policy

        if default_app_management_policy:
            report = CheckReportM365(
                self.metadata(),
                resource=default_app_management_policy,
                resource_name="Default App Management Policy",
                resource_id=default_app_management_policy.id
                or entra_client.tenant_domain,
            )
            report.status = "FAIL"
            report.status_extended = "Default app management policy is not enabled, allowing applications and service principals to be created without credential restrictions."

            if default_app_management_policy.is_enabled:
                report.status = "PASS"
                report.status_extended = "Default app management policy is enabled, enforcing credential restrictions on applications and service principals."

            findings.append(report)

        return findings
