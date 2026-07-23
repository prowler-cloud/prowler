from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessPolicyState,
    SignInFrequencyInterval,
    SignInFrequencyType,
)

# Maximum allowed reauthentication window (CIS: 7 days or less).
MAX_SIGN_IN_FREQUENCY_DAYS = 7
MAX_SIGN_IN_FREQUENCY_HOURS = MAX_SIGN_IN_FREQUENCY_DAYS * 24


class entra_conditional_access_policy_sign_in_frequency_all_users(Check):
    """Check if a Conditional Access policy enforces sign-in frequency for all users.

    This check ensures that at least one enabled Conditional Access policy targets
    all users and all resources and enforces a sign-in frequency of 7 days or less,
    limiting how long an authenticated session remains valid before reauthentication.

    - PASS: An enabled Conditional Access policy enforces sign-in frequency of 7 days
      or less for all users.
    - FAIL: No Conditional Access policy enforces sign-in frequency of 7 days or less
      for all users.
    """

    def _is_within_limit(self, sign_in_frequency) -> bool:
        """Return True if the sign-in frequency is 7 days or less."""
        if not sign_in_frequency or not sign_in_frequency.is_enabled:
            return False

        if sign_in_frequency.interval == SignInFrequencyInterval.EVERY_TIME:
            return True

        if sign_in_frequency.frequency is None:
            return False

        if sign_in_frequency.type == SignInFrequencyType.DAYS:
            return sign_in_frequency.frequency <= MAX_SIGN_IN_FREQUENCY_DAYS

        if sign_in_frequency.type == SignInFrequencyType.HOURS:
            return sign_in_frequency.frequency <= MAX_SIGN_IN_FREQUENCY_HOURS

        return False

    def execute(self) -> list[CheckReportM365]:
        """Execute the check to verify sign-in frequency is enforced for all users.

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
        report.status_extended = "No Conditional Access Policy enforces a sign-in frequency of 7 days or less for all users."

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

            # A policy scoped to risky sign-ins/users does not enforce periodic
            # reauthentication for all sessions, so it does not satisfy this control.
            if (
                policy.conditions.sign_in_risk_levels
                or policy.conditions.user_risk_levels
            ):
                continue

            if not self._is_within_limit(policy.session_controls.sign_in_frequency):
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )
            if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                report.status = "FAIL"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' enforces sign-in frequency but is in report-only mode."
            else:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' enforces a sign-in frequency of 7 days or less for all users."
                break

        findings.append(report)
        return findings
