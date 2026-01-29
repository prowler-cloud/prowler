from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    ConditionalAccessPolicyState,
    DeviceFilter,
    DeviceFilterMode,
    SignInFrequencyInterval,
)


class entra_conditional_access_policy_enforce_sign_in_frequency(Check):
    """Check if at least one Conditional Access policy enforces sign-in frequency for non-corporate devices.

    This check evaluates whether the tenant has a Conditional Access policy that:
    - Is enabled
    - Targets all users and all applications
    - Has sign-in frequency enabled with time-based interval
    - Targets non-corporate devices via device filter
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
        report.status_extended = "No Conditional Access Policy enforces sign-in frequency for non-corporate devices."

        for policy in entra_client.conditional_access_policies.values():
            if policy.state == ConditionalAccessPolicyState.DISABLED:
                continue

            if not policy.session_controls.sign_in_frequency.is_enabled:
                continue

            if (
                policy.session_controls.sign_in_frequency.interval
                != SignInFrequencyInterval.TIME_BASED
            ):
                continue

            if "All" not in policy.conditions.user_conditions.included_users:
                continue

            if (
                "All"
                not in policy.conditions.application_conditions.included_applications
            ):
                continue

            if not self._targets_non_corporate_devices(policy.conditions.device_filter):
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.display_name,
                resource_id=policy.id,
            )
            if policy.state == ConditionalAccessPolicyState.ENABLED_FOR_REPORTING:
                report.status = "FAIL"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' is configured to enforce sign-in frequency for non-corporate devices but is in report-only mode."
            else:
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy '{policy.display_name}' enforces sign-in frequency for non-corporate devices."
                break

        findings.append(report)
        return findings

    def _targets_non_corporate_devices(self, device_filter: DeviceFilter) -> bool:
        """Check if the device filter targets non-corporate devices.

        Non-corporate devices are identified by targeting devices that are:
        - Not Hybrid Azure AD joined (device.trustType != "ServerAD")
        - Not compliant (device.isCompliant != True)

        Args:
            device_filter: The device filter from the conditional access policy.

        Returns:
            True if the filter targets non-corporate devices, False otherwise.
        """
        if not device_filter or not device_filter.rule:
            return False

        rule = device_filter.rule.lower()
        mode = device_filter.mode

        # Include mode: should target non-corporate devices directly
        if mode == DeviceFilterMode.INCLUDE:
            targets_non_compliant = (
                "device.iscompliant" in rule and "-ne" in rule and "true" in rule
            )
            targets_non_hybrid = (
                "device.trusttype" in rule and "-ne" in rule and "serverad" in rule
            )
            if targets_non_compliant or targets_non_hybrid:
                return True

        # Exclude mode: should exclude corporate devices (equivalent to targeting non-corporate)
        elif mode == DeviceFilterMode.EXCLUDE:
            excludes_compliant = (
                "device.iscompliant" in rule and "-eq" in rule and "true" in rule
            )
            excludes_hybrid = (
                "device.trusttype" in rule and "-eq" in rule and "serverad" in rule
            )
            if excludes_compliant or excludes_hybrid:
                return True

        return False
