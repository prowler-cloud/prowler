import re

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessPolicyState,
    DeviceFilterMode,
)

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


class entra_conditional_access_policy_non_corporate_device_persistent_browser_disabled(
    Check,
):
    """Check if at least one Conditional Access policy enforces a non-persistent browser session for non-corporate devices.

    This check verifies that the tenant has at least one enabled Conditional Access policy
    that sets the persistent browser session to "never" targeting all users and all
    applications, with a device filter scoping the policy to non-corporate (unmanaged) devices.

    - PASS: At least one enabled policy enforces a non-persistent browser session with a
            device filter targeting non-corporate devices, for all users and all applications.
    - FAIL: No enabled policy meets the non-persistent browser session criteria for
            non-corporate devices, or the only qualifying policies are in report-only mode.
    - MANUAL: Conditional Access policies could not be fully read.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check for non-persistent browser session enforcement in Conditional Access policies.

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
        report.status_extended = "No Conditional Access Policy enforces a non-persistent browser session for non-corporate devices."

        qualifying_report_only = None

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

            persistent_browser = policy.session_controls.persistent_browser
            if not (
                persistent_browser.is_enabled
                and persistent_browser.mode.lower() == "never"
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
                patterns = NON_CORPORATE_INCLUDE_PATTERNS
            elif device_conditions.device_filter_mode == DeviceFilterMode.EXCLUDE:
                patterns = CORPORATE_EXCLUDE_PATTERNS
            else:
                continue

            if not any(re.search(pattern, rule) for pattern in patterns):
                continue

            if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                qualifying_report_only = policy
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )
            report.status = "PASS"
            report.status_extended = f"Conditional Access Policy {policy.display_name} enforces a non-persistent browser session for non-corporate devices."
            break

        if report.status != "PASS" and qualifying_report_only:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=qualifying_report_only,
                resource_name=qualifying_report_only.display_name,
                resource_id=qualifying_report_only.id,
            )
            report.status = "FAIL"
            report.status_extended = f"Conditional Access Policy {qualifying_report_only.display_name} reports a non-persistent browser session for non-corporate devices but does not enforce it."

        if report.status != "PASS" and entra_client.conditional_access_policies_error:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Conditional Access Policies",
                resource_id="conditionalAccessPolicies",
            )
            report.status = "MANUAL"
            report.status_extended = f"Conditional Access policies could not be fully read: {entra_client.conditional_access_policies_error}. Verify that Policy.Read.All permission is granted and Entra ID P1 license is available."

        findings.append(report)
        return findings
