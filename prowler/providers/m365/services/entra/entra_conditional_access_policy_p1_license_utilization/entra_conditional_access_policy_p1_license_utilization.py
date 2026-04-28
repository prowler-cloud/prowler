from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_conditional_access_policy_p1_license_utilization(Check):
    """Check if Premium license entitlements cover Conditional Access utilization.

    Compares the total entitled Microsoft Entra ID Premium licenses (P1 + P2,
    since P2 includes P1) against the number of users actively utilising
    Conditional Access (regular plus guest users).

    - PASS: total premium license entitlements cover all Conditional Access users.
    - FAIL: more users utilize Conditional Access than entitled premium licenses.
    - MANUAL: license insight unavailable, typically because the tenant has no
      P1/P2 license (Microsoft Graph returns 403 ``missingLicense``) or the
      ``Reports.Read.All`` permission was not granted.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the premium license utilization check.

        Returns:
            A list with a single report describing the licensing coverage.
        """
        findings = []

        insight = entra_client.premium_license_insight

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=insight or {},
            resource_name="Premium License Insight",
            resource_id="azureADPremiumLicenseInsight",
        )

        if insight is None:
            report.status = "MANUAL"
            report.status_extended = (
                "Could not retrieve Azure AD Premium license insight. "
                "Verify the tenant has at least one Microsoft Entra ID P1 or P2 "
                "license and that Reports.Read.All permission is granted."
            )
        elif insight.total_license_count >= insight.conditional_access_users_count:
            report.status = "PASS"
            report.status_extended = (
                f"Premium license entitlements ({insight.total_license_count}) "
                f"cover all Conditional Access users "
                f"({insight.conditional_access_users_count})."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                f"Premium license entitlements ({insight.total_license_count}) "
                f"do not cover all Conditional Access users "
                f"({insight.conditional_access_users_count})."
            )

        findings.append(report)
        return findings
