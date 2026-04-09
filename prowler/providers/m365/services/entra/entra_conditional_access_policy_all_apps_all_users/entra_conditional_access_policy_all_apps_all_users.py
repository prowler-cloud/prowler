from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
)


class entra_conditional_access_policy_all_apps_all_users(Check):
    """Check if at least one Conditional Access policy covers all cloud apps and all users.

    This check verifies that at least one enabled Conditional Access policy
    targets all cloud applications and all users, ensuring baseline protection
    across the entire tenant. Policies that only require a password change are
    excluded because they do not provide meaningful access control.

    - PASS: An enabled Conditional Access policy covers all apps and all users with no exclusions.
    - MANUAL: A policy targets all apps and all users but includes exclusions that require review.
    - FAIL: No Conditional Access policy provides coverage for all apps and all users.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check to verify Conditional Access coverage for all apps and all users.

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
        report.status_extended = "No Conditional Access Policy covers all cloud apps and all users."

        manual_policy = None
        reporting_only_policy = None

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            application_conditions = policy.conditions.application_conditions
            user_conditions = policy.conditions.user_conditions
            if not application_conditions or not user_conditions:
                continue

            if "All" not in application_conditions.included_applications:
                continue

            if "All" not in user_conditions.included_users:
                continue

            # Exclude policies that only require a password change,
            # as they do not provide meaningful access control.
            if policy.grant_controls.built_in_controls == [
                ConditionalAccessGrantControl.PASSWORD_CHANGE
            ]:
                continue

            has_exclusions = bool(
                application_conditions.excluded_applications
                or user_conditions.excluded_users
                or user_conditions.excluded_groups
                or user_conditions.excluded_roles
            )

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )

            if has_exclusions:
                if manual_policy is None:
                    manual_policy = policy
                continue

            if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                if reporting_only_policy is None:
                    reporting_only_policy = policy
            else:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' covers all cloud apps and all users."
                break
        else:
            if manual_policy is not None:
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=manual_policy,
                    resource_name=manual_policy.display_name,
                    resource_id=manual_policy.id,
                )
                report.status = "MANUAL"
                report.status_extended = (
                    f"Conditional Access Policy '{manual_policy.display_name}' "
                    "targets all cloud apps and all users but includes exclusions. "
                    "Review excluded users/groups/roles/applications and verify "
                    "compensating policies protect excluded identities and apps."
                )
            elif reporting_only_policy is not None:
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=reporting_only_policy,
                    resource_name=reporting_only_policy.display_name,
                    resource_id=reporting_only_policy.id,
                )
                report.status = "FAIL"
                report.status_extended = (
                    f"Conditional Access Policy '{reporting_only_policy.display_name}' "
                    "covers all cloud apps and all users but is only in report-only mode."
                )

        findings.append(report)
        return findings
