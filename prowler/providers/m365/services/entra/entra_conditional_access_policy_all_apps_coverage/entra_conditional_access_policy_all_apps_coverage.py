from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
)


class entra_conditional_access_policy_all_apps_coverage(Check):
    """Check if at least one Conditional Access policy targets all cloud apps.

    This check verifies that at least one Conditional Access policy is configured
    to target all cloud applications. Having a policy that applies to all apps
    ensures comprehensive coverage and prevents gaps when new applications are
    onboarded.

    - PASS: At least one enabled Conditional Access policy targets all cloud apps.
    - FAIL: No Conditional Access policy targets all cloud apps, or only
      report-only policies exist.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check to verify all cloud apps coverage.

        Iterates over the Conditional Access Policies and generates a report
        indicating whether at least one policy targets all cloud applications.

        Returns:
            list[CheckReportM365]: A list containing the result of the check.
        """
        findings = []
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="Conditional Access Policies",
            resource_id="conditionalAccessPolicies",
        )
        report.status = "FAIL"
        report.status_extended = "No Conditional Access Policy targets all cloud apps."

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
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' targets all cloud apps but is only configured for reporting."
            else:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' targets all cloud apps."
                break

        findings.append(report)
        return findings
