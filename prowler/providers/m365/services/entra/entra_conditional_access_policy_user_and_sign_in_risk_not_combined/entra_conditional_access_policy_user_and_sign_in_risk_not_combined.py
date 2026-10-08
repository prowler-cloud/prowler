from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessPolicyState,
)


class entra_conditional_access_policy_user_and_sign_in_risk_not_combined(Check):
    """Ensure Conditional Access policies do not combine user risk and sign-in risk conditions.

    All conditions in a Conditional Access policy are ANDed together. A policy that
    sets both user risk and sign-in risk only fires when both risks are present
    simultaneously, leaving most risk events uncovered. Microsoft recommends separate
    policies for each risk type.

    - PASS (per policy): The policy uses only one kind of risk condition.
    - PASS (tenant-level): No enabled or report-only policy uses risk conditions.
    - FAIL (per policy): The policy combines both user risk and sign-in risk conditions.
    - MANUAL (tenant-level): Conditional Access policies could not be read.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check logic.

        Iterates over all enabled or report-only Conditional Access policies that use
        at least one risk condition and verifies that user risk and sign-in risk are
        not combined in a single policy.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        found_risk_policy = False

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            has_user_risk = bool(policy.conditions.user_risk_levels)
            has_sign_in_risk = bool(policy.conditions.sign_in_risk_levels)

            if not has_user_risk and not has_sign_in_risk:
                continue

            found_risk_policy = True

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )

            if has_user_risk and has_sign_in_risk:
                user_levels = ", ".join(
                    level.value for level in policy.conditions.user_risk_levels
                )
                sign_in_levels = ", ".join(
                    level.value for level in policy.conditions.sign_in_risk_levels
                )
                report_only_note = (
                    " (report-only)"
                    if policy.state
                    == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING
                    else ""
                )
                report.status = "FAIL"
                report.status_extended = (
                    f"Conditional Access Policy '{policy.display_name}'{report_only_note} "
                    f"combines user risk ({user_levels}) and sign-in risk ({sign_in_levels}) "
                    f"in a single policy, so it only applies when both risks are present."
                )
            else:
                risk_type = "user" if has_user_risk else "sign-in"
                report.status = "PASS"
                report.status_extended = (
                    f"Conditional Access Policy '{policy.display_name}' "
                    f"configures {risk_type} risk on its own."
                )

            findings.append(report)

        if not found_risk_policy:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Conditional Access Policies",
                resource_id="conditionalAccessPolicies",
            )

            if entra_client.conditional_access_policies_error:
                report.status = "MANUAL"
                report.status_extended = (
                    "Could not determine whether Conditional Access policies combine "
                    "user risk and sign-in risk: the policies could not be read "
                    f"({entra_client.conditional_access_policies_error}). Verify that "
                    "Policy.Read.All permission is granted and Entra ID P1 is licensed."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    "No enabled Conditional Access policy uses risk conditions; "
                    "no policy combines user risk and sign-in risk."
                )

            findings.append(report)

        return findings
