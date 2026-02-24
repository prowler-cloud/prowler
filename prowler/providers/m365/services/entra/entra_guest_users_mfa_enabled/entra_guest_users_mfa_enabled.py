from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessGrantControl,
    ConditionalAccessPolicy,
    ConditionalAccessPolicyState,
    GuestOrExternalUserType,
)

ALL_GUEST_TYPES = {guest_type for guest_type in GuestOrExternalUserType}


class entra_guest_users_mfa_enabled(Check):
    """Conditional Access policy enforces MFA for guest users.

    This check verifies that at least one enabled Conditional Access policy
    requires multifactor authentication for all guest and external user types
    across all cloud applications.

    - PASS: An enabled policy requires MFA for all guest user types.
    - FAIL: No enabled policy requires MFA for guest users, or matching
      policies are only in report-only mode.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the guest users MFA check.

        Returns:
            A list containing a single report with the result of the check.
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
            "No Conditional Access Policy enforces MFA for guest users."
        )

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            if not self._policy_targets_guests(policy):
                continue

            if (
                "All"
                not in policy.conditions.application_conditions.included_applications
            ):
                continue

            if not self._policy_requires_mfa(policy):
                continue

            if self._policy_excludes_guests(policy):
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )
            if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                report.status = "FAIL"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' reports MFA requirement for guest users but does not enforce it."
            else:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' enforces MFA for guest users."
                break

        findings.append(report)
        return findings

    @staticmethod
    def _policy_targets_guests(policy: ConditionalAccessPolicy) -> bool:
        """Check if a policy targets guest users.

        A policy targets guests if it either applies to all users or explicitly
        includes all guest and external user types.
        """
        if "All" in policy.conditions.user_conditions.included_users:
            return True

        guests_config = (
            policy.conditions.user_conditions.included_guests_or_external_users
        )
        if guests_config and ALL_GUEST_TYPES.issubset(
            set(guests_config.guest_or_external_user_types)
        ):
            return True

        return False

    @staticmethod
    def _policy_requires_mfa(policy: ConditionalAccessPolicy) -> bool:
        """Check if a policy requires MFA via built-in controls or authentication strength."""
        if (
            ConditionalAccessGrantControl.MFA
            in policy.grant_controls.built_in_controls
        ):
            return True

        if policy.grant_controls.authentication_strength is not None:
            return True

        return False

    @staticmethod
    def _policy_excludes_guests(policy: ConditionalAccessPolicy) -> bool:
        """Check if a policy excludes guest or external user types."""
        excluded = (
            policy.conditions.user_conditions.excluded_guests_or_external_users
        )
        if excluded and excluded.guest_or_external_user_types:
            return True
        return False
