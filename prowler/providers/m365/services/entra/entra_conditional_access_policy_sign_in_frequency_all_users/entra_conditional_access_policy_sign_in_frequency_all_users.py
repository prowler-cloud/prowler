from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ClientAppType,
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

    def _has_restricted_scope(self, conditions) -> bool:
        """Return True when policy conditions exclude part of the session scope."""
        platforms = conditions.platform_conditions
        platform_restricted = bool(
            platforms
            and (
                platforms.exclude_platforms
                or (
                    platforms.include_platforms
                    and "all" not in platforms.include_platforms
                )
            )
        )
        client_app_types = conditions.client_app_types or []
        client_app_restricted = bool(
            client_app_types and ClientAppType.ALL not in client_app_types
        )
        locations = conditions.locations
        location_restricted = bool(
            locations
            and (
                locations.exclude_locations
                or (
                    locations.include_locations
                    and "All" not in locations.include_locations
                )
            )
        )
        device_conditions = conditions.device_conditions
        device_restricted = bool(
            device_conditions
            and (
                device_conditions.device_filter_mode
                or device_conditions.device_filter_rule
            )
        )
        authentication_flows = conditions.authentication_flows
        authentication_flow_restricted = bool(
            authentication_flows and authentication_flows.transfer_methods
        )
        user_conditions = conditions.user_conditions
        user_restricted = bool(
            user_conditions.excluded_users
            or user_conditions.excluded_groups
            or user_conditions.excluded_roles
            or user_conditions.excluded_guests_or_external_users
        )
        application_restricted = bool(
            conditions.application_conditions.included_user_actions
        )

        return bool(
            platform_restricted
            or client_app_restricted
            or location_restricted
            or device_restricted
            or authentication_flow_restricted
            or conditions.insider_risk_levels
            or user_restricted
            or application_restricted
        )

    def execute(self) -> list[CheckReportM365]:
        """Execute the check to verify sign-in frequency is enforced for all users.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        for policy in entra_client.conditional_access_policies.values():
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )
            report.status = "FAIL"
            report.status_extended = f"Conditional Access Policy '{policy.display_name}' does not enforce a sign-in frequency of 7 days or less for all users."

            enforces_sign_in_frequency = (
                policy.state != ConditionalAccessPolicyState.DISABLED
                and "All" in policy.conditions.user_conditions.included_users
                and "All"
                in policy.conditions.application_conditions.included_applications
                and not policy.conditions.application_conditions.excluded_applications
                and not policy.conditions.sign_in_risk_levels
                and not policy.conditions.user_risk_levels
                and not self._has_restricted_scope(policy.conditions)
                and self._is_within_limit(policy.session_controls.sign_in_frequency)
            )
            if enforces_sign_in_frequency:
                if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                    report.status_extended = f"Conditional Access Policy '{policy.display_name}' enforces sign-in frequency but is in report-only mode."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Conditional Access Policy '{policy.display_name}' enforces a sign-in frequency of 7 days or less for all users."

            findings.append(report)
        return findings
