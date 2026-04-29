import re

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessPolicyState,
    DeviceFilterMode,
    SignInFrequencyInterval,
)


class entra_conditional_access_policy_corporate_device_sign_in_frequency_enforced(
    Check
):
    """Check if at least one Conditional Access policy enforces sign-in frequency for non-corporate devices.

    This check verifies that the tenant has at least one enabled Conditional Access policy
    that enforces time-based sign-in frequency targeting all users and all applications,
    with a device filter scoping the policy to non-corporate (unmanaged) devices.

    - PASS: At least one enabled policy enforces sign-in frequency with a device filter
            targeting non-corporate devices, for all users and all applications.
    - FAIL: No enabled policy meets the sign-in frequency enforcement criteria for
            non-corporate devices.
    """

    NON_CORPORATE_INCLUDE_PATTERNS = (
        r"device\.iscompliant\s*-ne\s*true",
        r"device\.iscompliant\s*-eq\s*false",
        r'device\.trusttype\s*-ne\s*"serverad"',
        r"device\.trusttype\s*-ne\s*'serverad'",
    )
    CORPORATE_EXCLUDE_PATTERNS = (
        r"device\.iscompliant\s*-eq\s*true",
        r'device\.trusttype\s*-eq\s*"serverad"',
        r"device\.trusttype\s*-eq\s*'serverad'",
    )

    def execute(self) -> list[CheckReportM365]:
        """Execute the check for sign-in frequency enforcement in Conditional Access policies.

        Returns:
            list[CheckReportM365]: A list containing the result of the check.
        """
        findings = []
        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="Conditional Access Policies",
            resource_id="conditionalAccessPolicies",
        )
        report.status = "FAIL"
        report.status_extended = "No Conditional Access Policy enforces sign-in frequency for non-corporate devices."

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

            sign_in_freq = policy.session_controls.sign_in_frequency
            if not (
                sign_in_freq.is_enabled
                and sign_in_freq.interval == SignInFrequencyInterval.TIME_BASED
            ):
                continue

            device_conditions = policy.conditions.device_conditions
            if (
                not device_conditions
                or not device_conditions.device_filter_mode
                or not device_conditions.device_filter_rule
            ):
                continue

            rule = device_conditions.device_filter_rule.lower()
            if device_conditions.device_filter_mode == DeviceFilterMode.INCLUDE:
                patterns = self.NON_CORPORATE_INCLUDE_PATTERNS
            elif device_conditions.device_filter_mode == DeviceFilterMode.EXCLUDE:
                patterns = self.CORPORATE_EXCLUDE_PATTERNS
            else:
                continue

            if not any(re.search(pattern, rule) for pattern in patterns):
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )
            if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                report.status = "FAIL"
                report.status_extended = f"Conditional Access Policy {policy.display_name} reports sign-in frequency for non-corporate devices but does not enforce it."
            else:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy {policy.display_name} enforces sign-in frequency for non-corporate devices."
                break

        findings.append(report)
        return findings
