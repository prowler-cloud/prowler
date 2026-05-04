from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ContinuousAccessEvaluationMode,
    ConditionalAccessPolicyState,
)


class entra_continuous_access_evaluation_enabled(Check):
    """Check if at least one Conditional Access policy has Continuous Access Evaluation enabled.

    This check ensures that at least one Conditional Access policy has Continuous Access
    Evaluation (CAE) configured in its session controls to allow Microsoft Entra ID to
    revoke access in near real-time when critical events occur.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check to verify CAE is enabled in Conditional Access policies.

        Returns:
            list[CheckReportM365]: A list containing the results of the check.
        """
        findings = []
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="Conditional Access Policies",
            resource_id="conditionalAccessPolicies",
        )
        report.status = "FAIL"
        report.status_extended = (
            "No Conditional Access Policy has Continuous Access Evaluation enabled."
        )

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            if "All" not in policy.conditions.user_conditions.included_users:
                continue

            if (
                "All"
                not in policy.conditions.application_conditions.included_applications
            ):
                continue

            cae = policy.session_controls.continuous_access_evaluation

            if not cae or not cae.is_enabled:
                continue

            if cae.mode == ContinuousAccessEvaluationMode.DISABLED:
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )

            if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                report.status = "FAIL"
                report.status_extended = (
                    f"Conditional Access Policy '{policy.display_name}' reports "
                    "Continuous Access Evaluation but does not enforce it."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Conditional Access Policy '{policy.display_name}' has "
                    "Continuous Access Evaluation enabled."
                )
                break

        findings.append(report)
        return findings
