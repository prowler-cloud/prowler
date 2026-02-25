from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
    RiskLevel,
    SignInFrequencyInterval,
)


class entra_conditional_access_policy_risky_sign_in_mfa(Check):
    """Check if a Conditional Access policy requires MFA for medium and high risk sign-ins.

    This check verifies that at least one enabled Conditional Access policy is configured to
    require multifactor authentication for risky sign-ins, targeting all users and all applications,
    with sign-in frequency set to every time to force re-authentication.
    - PASS: An enabled CA policy requires MFA for medium and high risk sign-ins with every-time sign-in frequency.
    - FAIL: No CA policy addresses risky sign-ins with MFA requirement, or the policy is missing required conditions.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check for Conditional Access policy requiring MFA on risky sign-ins.

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
        report.status_extended = "No Conditional Access Policy requires MFA for risky sign-ins."

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

            if (
                ConditionalAccessGrantControl.MFA
                not in policy.grant_controls.built_in_controls
            ):
                continue

            if (
                SignInFrequencyInterval.EVERY_TIME
                != policy.session_controls.sign_in_frequency.interval
            ):
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )

            has_high = RiskLevel.HIGH in policy.conditions.sign_in_risk_levels
            has_medium = RiskLevel.MEDIUM in policy.conditions.sign_in_risk_levels

            if not has_high or not has_medium:
                report.status = "FAIL"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' requires MFA but does not cover both high and medium sign-in risk levels."
            elif policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                report.status = "FAIL"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' requires MFA for high and medium risk sign-ins but is set to report-only mode and does not enforce protection."
            else:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' requires MFA for high and medium risk sign-ins and enforces re-authentication every time."
                break

        findings.append(report)

        return findings
