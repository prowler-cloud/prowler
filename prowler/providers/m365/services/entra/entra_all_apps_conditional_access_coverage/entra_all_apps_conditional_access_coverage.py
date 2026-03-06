from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
)


class entra_all_apps_conditional_access_coverage(Check):
    """Check if at least one Conditional Access policy targets all cloud apps.

    This check iterates over all Conditional Access policies and collects those
    that target all cloud applications. A single finding is produced listing
    every matching policy name.

    - PASS: At least one fully enabled policy targets all cloud apps.
    - FAIL: No policy targets all cloud apps, or only report-only policies do.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check to verify all cloud apps coverage.

        Returns:
            list[CheckReportM365]: A single-element list with the result.
        """
        findings = []
        enabled_policies = []
        reporting_only_policies = []

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

            if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                reporting_only_policies.append(policy)
            else:
                enabled_policies.append(policy)

        if enabled_policies:
            policy_names = ", ".join(p.display_name for p in enabled_policies)
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Conditional Access Policies",
                resource_id="conditionalAccessPolicies",
            )
            report.status = "PASS"
            report.status_extended = (
                f"Conditional Access Policies targeting all cloud apps: {policy_names}."
            )
        elif reporting_only_policies:
            policy_names = ", ".join(p.display_name for p in reporting_only_policies)
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Conditional Access Policies",
                resource_id="conditionalAccessPolicies",
            )
            report.status = "FAIL"
            report.status_extended = f"Conditional Access Policies targeting all cloud apps are only configured for reporting: {policy_names}."
        else:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Conditional Access Policies",
                resource_id="conditionalAccessPolicies",
            )
            report.status = "FAIL"
            report.status_extended = (
                "No Conditional Access Policy targets all cloud apps."
            )

        findings.append(report)
        return findings
