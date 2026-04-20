from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_conditional_access_policy_p2_license_utilization(Check):
    """Check P2-feature (risk-based Conditional Access) license coverage.

    Compares the number of users consuming **risk-based Conditional Access**
    (regular plus guest, exposed via ``p2FeatureUtilizations`` in
    ``reports/azureADPremiumLicenseInsight``) against the entitled
    Microsoft Entra ID P2 license count. P1 entitlements do **not** cover
    P2 features, so this check uses ``entitled_p2_license_count`` alone.

    For non-risk-based Conditional Access (P1), see
    ``entra_conditional_access_policy_p1_license_utilization``.

    - PASS: P2 entitlements cover all risk-based Conditional Access users.
    - FAIL: risk-based CA utilization exceeds entitled P2 licenses.
    - MANUAL: license insight unavailable, typically because the tenant has no
      P1/P2 license (Microsoft Graph returns 403 ``missingLicense``) or the
      ``Reports.Read.All`` permission was not granted.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the P2 license utilization check.

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
        elif insight.entitled_p2_license_count >= insight.p2_licenses_utilized:
            report.status = "PASS"
            report.status_extended = (
                f"P2 license entitlements ({insight.entitled_p2_license_count}) "
                f"cover all risk-based Conditional Access users "
                f"({insight.p2_licenses_utilized})."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                f"P2 license entitlements ({insight.entitled_p2_license_count}) "
                f"do not cover all risk-based Conditional Access users "
                f"({insight.p2_licenses_utilized})."
            )

        findings.append(report)
        return findings
