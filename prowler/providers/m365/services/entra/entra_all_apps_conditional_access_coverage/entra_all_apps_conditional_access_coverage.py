from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
)


class entra_all_apps_conditional_access_coverage(Check):
    """Check which Conditional Access policies target all cloud apps.

    This check reports all Conditional Access policies that are configured
    to target all cloud applications. Having a policy that applies to all apps
    ensures comprehensive coverage and prevents gaps when new applications are
    onboarded.

    - PASS: An enabled Conditional Access policy targets all cloud apps.
    - FAIL (no policies): No Conditional Access policy targets all cloud apps.
    - FAIL (report-only): A policy targets all cloud apps but is only in
      report-only mode.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check to report all policies targeting all cloud apps.

        Iterates over the Conditional Access Policies and generates a finding
        for each policy that targets all cloud applications.

        Returns:
            list[CheckReportM365]: A list containing the results of the check.
        """
        findings = []

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            if (
                "All"
                not in policy.conditions.application_conditions.included_applications
            ):
                continue

            # Skip policies that require password change
            if (
                ConditionalAccessGrantControl.PASSWORD_CHANGE
                in policy.grant_controls.built_in_controls
            ):
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )
            if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                report.status = "FAIL"
                report.status_extended = f"Conditional Access Policy {policy.display_name} targets all cloud apps but is only configured for reporting."
            else:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy {policy.display_name} targets all cloud apps."

            findings.append(report)

        if not findings:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Conditional Access Policies",
                resource_id="conditionalAccessPolicies",
            )
            report.status = "FAIL"
            report.status_extended = "No Conditional Access Policy targets all cloud apps."
            findings.append(report)

        return findings
