from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
    RiskLevel,
)


class entra_conditional_access_policy_block_high_medium_sign_in_risk(Check):
    """Check if a Conditional Access policy blocks high and medium sign-in risk.

    This check ensures that at least one enabled Conditional Access policy targets
    all users and all resources with the sign-in risk condition set to High and
    Medium, and blocks access, mitigating risky sign-in attempts detected by
    Microsoft Entra ID Protection.

    - PASS: An enabled Conditional Access policy blocks high and medium sign-in risk.
    - FAIL: No Conditional Access policy blocks high and medium sign-in risk.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check to verify high and medium sign-in risk is blocked.

        Returns:
            A list of reports containing the result of the check.
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
            "No Conditional Access Policy blocks high and medium sign-in risk."
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

            if policy.conditions.application_conditions.excluded_applications:
                continue

            if not {RiskLevel.HIGH, RiskLevel.MEDIUM}.issubset(
                set(policy.conditions.sign_in_risk_levels)
            ):
                continue

            if (
                ConditionalAccessGrantControl.BLOCK
                in policy.grant_controls.built_in_controls
            ):
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=policy,
                    resource_name=policy.display_name,
                    resource_id=policy.id,
                )
                if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                    report.status = "FAIL"
                    report.status_extended = f"Conditional Access Policy '{policy.display_name}' reports high and medium sign-in risk but does not block it."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Conditional Access Policy '{policy.display_name}' blocks high and medium sign-in risk."
                    break

        findings.append(report)
        return findings
