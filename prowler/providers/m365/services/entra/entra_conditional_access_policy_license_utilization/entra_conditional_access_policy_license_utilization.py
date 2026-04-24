from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_conditional_access_policy_license_utilization(Check):
    """Check if all users utilizing Entra ID P2 features are properly licensed.

    This check validates that the number of users consuming P2-level Conditional
    Access features (risk-based Conditional Access) does not exceed the number
    of entitled P2 licenses in the tenant.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the P2 license utilization check.

        Compares the number of users actively consuming P2 features against the
        number of entitled P2 licenses. If utilization exceeds entitlement, the
        tenant is under-licensed and the check fails.

        Returns:
            list[CheckReportM365]: A list containing the result of the check.
        """
        findings = []

        insight = entra_client.premium_license_insight

        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="Premium License Insight",
            resource_id="azureADPremiumLicenseInsight",
        )

        if insight is None:
            report.status = "FAIL"
            report.status_extended = "Could not retrieve premium license insight data, ensure the required permissions are granted."
        elif (
            insight.entitled_p2_license_count == 0
            and insight.p2_licenses_utilized > 0
        ):
            report.status = "FAIL"
            report.status_extended = f"No P2 licenses are entitled but {insight.p2_licenses_utilized} user(s) are consuming P2 features."
        elif insight.p2_licenses_utilized > insight.entitled_p2_license_count:
            report.status = "FAIL"
            report.status_extended = (
                f"P2 license utilization ({insight.p2_licenses_utilized}) exceeds "
                f"entitled P2 licenses ({insight.entitled_p2_license_count}), "
                f"{insight.p2_licenses_utilized - insight.entitled_p2_license_count} "
                f"user(s) are consuming P2 features without a license."
            )
        else:
            report.status = "PASS"
            report.status_extended = (
                f"P2 license utilization ({insight.p2_licenses_utilized}) is within "
                f"entitled P2 licenses ({insight.entitled_p2_license_count})."
            )

        findings.append(report)

        return findings
