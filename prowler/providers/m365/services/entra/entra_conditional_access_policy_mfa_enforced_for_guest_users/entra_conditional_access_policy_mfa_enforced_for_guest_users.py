"""Check if at least one Conditional Access policy requires MFA for guest users."""

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ALL_GUEST_USER_TYPES,
    ConditionalAccessGrantControl,
    ConditionalAccessPolicyState,
    ExternalTenantsMembershipKind,
)


class entra_conditional_access_policy_mfa_enforced_for_guest_users(Check):
    """Check if at least one enabled Conditional Access policy requires MFA for guest users.

    This check verifies that the Microsoft Entra tenant has at least one
    enabled Conditional Access policy that requires multifactor authentication
    (MFA) for all guest and external user types across all cloud applications.

    - PASS: At least one enabled CA policy requires MFA for all guest user types.
    - FAIL: No enabled CA policy enforces MFA for guest users.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check logic.

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
            "No Conditional Access Policy requires MFA for guest users."
        )

        reporting_policy = None

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            # Policy must require MFA (built-in control or authentication strength)
            # and must not only require password change.
            has_mfa = (
                ConditionalAccessGrantControl.MFA
                in policy.grant_controls.built_in_controls
            )
            has_auth_strength = (
                policy.grant_controls.authentication_strength is not None
            )
            only_password_change = policy.grant_controls.built_in_controls == [
                ConditionalAccessGrantControl.PASSWORD_CHANGE
            ]

            if not (has_mfa or has_auth_strength) or only_password_change:
                continue

            # Policy must target all cloud applications.
            if not policy.conditions.application_conditions:
                continue

            if (
                "All"
                not in policy.conditions.application_conditions.included_applications
            ):
                continue

            # Policy must target guest users: either include all users, or
            # specifically include all guest/external user types.
            targets_all_users = (
                "All" in policy.conditions.user_conditions.included_users
            )
            targets_guests_via_include = (
                "GuestsOrExternalUsers"
                in policy.conditions.user_conditions.included_users
            )
            excludes_all_guests = (
                "GuestsOrExternalUsers"
                in policy.conditions.user_conditions.excluded_users
            )

            included_guests = (
                policy.conditions.user_conditions.included_guests_or_external_users
            )
            targets_all_guest_types = included_guests is not None and (
                ALL_GUEST_USER_TYPES
                <= set(included_guests.guest_or_external_user_types)
                and included_guests.external_tenants_membership_kind
                in (None, ExternalTenantsMembershipKind.ALL)
            )

            if not (
                targets_all_users
                or targets_guests_via_include
                or targets_all_guest_types
            ):
                continue

            # Policy must not exclude guest/external user types.
            excluded_guests = (
                policy.conditions.user_conditions.excluded_guests_or_external_users
            )
            if excludes_all_guests or (
                excluded_guests is not None
                and excluded_guests.guest_or_external_user_types
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
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' requires MFA for guest users."
                break

            if (
                policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING
                and reporting_policy is None
            ):
                reporting_policy = policy

        if report.status == "FAIL" and reporting_policy:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=reporting_policy,
                resource_name=reporting_policy.display_name,
                resource_id=reporting_policy.id,
            )
            report.status = "FAIL"
            report.status_extended = f"Conditional Access Policy '{reporting_policy.display_name}' targets guest users with MFA but is only in report-only mode."

        findings.append(report)
        return findings
