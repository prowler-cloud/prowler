from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
    GrantControlOperator,
)

INTUNE_ENROLLMENT_APP_ID = "d4ebce55-015a-49b5-a083-c84d1797ae8c"
MICROSOFT_INTUNE_APP_ID = "0000000a-0000-0000-c000-000000000000"


class entra_conditional_access_policy_intune_enrollment_mfa_required(Check):
    """Ensure MFA is required for Intune enrollment."""

    def execute(self) -> list[CheckReportM365]:
        findings = []

        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="Conditional Access Policies",
            resource_id="conditionalAccessPolicies",
        )
        report.status = "FAIL"
        report.status_extended = (
            "No Conditional Access Policy requires MFA for Intune enrollment."
        )

        reporting_policy = None

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            if "All" not in policy.conditions.user_conditions.included_users:
                continue

            included_apps = (
                policy.conditions.application_conditions.included_applications
            )
            excluded_apps = (
                policy.conditions.application_conditions.excluded_applications
            )
            targets_intune = (
                INTUNE_ENROLLMENT_APP_ID in included_apps
                or MICROSOFT_INTUNE_APP_ID in included_apps
                or "All" in included_apps
            )
            excludes_intune = (
                INTUNE_ENROLLMENT_APP_ID in excluded_apps
                or MICROSOFT_INTUNE_APP_ID in excluded_apps
            )

            if not targets_intune or excludes_intune:
                continue

            if (
                ConditionalAccessGrantControl.MFA
                not in policy.grant_controls.built_in_controls
            ):
                continue

            # "Require MFA" means MFA must always be satisfied. Policies using
            # OR with additional controls make MFA optional and should not pass.
            if (
                policy.grant_controls.operator == GrantControlOperator.OR
                and len(policy.grant_controls.built_in_controls) > 1
            ):
                continue

            if policy.state == ConditionalAccessPolicyState.ENABLED:
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=policy,
                    resource_name=policy.display_name,
                    resource_id=policy.id,
                )
                report.status = "PASS"
                report.status_extended = (
                    f"Conditional Access Policy '{policy.display_name}' requires MFA "
                    "for Intune enrollment."
                )
                break

            if (
                policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING
                and reporting_policy is None
            ):
                reporting_policy = policy

        if report.status == "FAIL" and reporting_policy:
            report.status_extended = (
                f"Conditional Access Policy '{reporting_policy.display_name}' reports "
                "MFA for Intune enrollment but does not require it."
            )

        findings.append(report)
        return findings
