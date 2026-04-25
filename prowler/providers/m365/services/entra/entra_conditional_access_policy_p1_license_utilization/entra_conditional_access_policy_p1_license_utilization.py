from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_conditional_access_policy_p1_license_utilization(Check):
    """Check if P1 license entitlements cover Conditional Access utilization.

    Validates that the number of entitled Azure AD Premium P1 licenses
    is sufficient to cover all users actively utilizing Conditional Access.

    - PASS: P1 license entitlements cover all Conditional Access users.
    - FAIL: More users utilize Conditional Access than entitled P1 licenses.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the P1 license utilization check.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        insight = entra_client.premium_license_insight

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=insight if insight else {},
            resource_name="Premium License Insight",
            resource_id="azureADPremiumLicenseInsight",
        )

        if insight is None:
            report.status = "FAIL"
            report.status_extended = (
                "Could not retrieve Azure AD Premium license insight data. "
                "Verify that the tenant has a P1 or P2 license and that "
                "the required permissions are granted."
            )
        elif insight.p1_license_count >= insight.conditional_access_users_count:
            report.status = "PASS"
            report.status_extended = (
                f"P1 license entitlements ({insight.p1_license_count}) cover "
                f"all Conditional Access users ({insight.conditional_access_users_count})."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                f"P1 license entitlements ({insight.p1_license_count}) do not cover "
                f"all Conditional Access users ({insight.conditional_access_users_count})."
            )

        findings.append(report)
        return findings
