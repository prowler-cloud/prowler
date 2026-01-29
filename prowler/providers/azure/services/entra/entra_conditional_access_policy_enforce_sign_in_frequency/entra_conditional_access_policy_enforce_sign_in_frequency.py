from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client


class entra_conditional_access_policy_enforce_sign_in_frequency(Check):
    """
    Ensure at least one Conditional Access policy enforces sign-in frequency for non-corporate devices.

    This check evaluates whether the tenant has a Conditional Access policy that:
    - Is enabled
    - Targets all users and all applications
    - Has sign-in frequency enabled with time-based interval
    - Targets non-corporate devices via device filter

    - PASS: A policy meeting all criteria exists.
    - FAIL: No policy enforces sign-in frequency for non-corporate devices.
    """

    def execute(self) -> list[Check_Report_Azure]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        for (
            tenant_name,
            conditional_access_policies,
        ) in entra_client.conditional_access_policy.items():
            compliant_policy = None

            for policy in conditional_access_policies.values():
                # Check if policy is enabled
                if policy.state != "enabled":
                    continue

                # Check if sign-in frequency is enabled with time-based interval
                if not policy.sign_in_frequency:
                    continue
                if not policy.sign_in_frequency.is_enabled:
                    continue
                if (
                    policy.sign_in_frequency.frequency_interval
                    and "timebased"
                    not in policy.sign_in_frequency.frequency_interval.lower()
                ):
                    continue

                # Check if targets all users
                if "All" not in policy.users.get("include", []):
                    continue

                # Check if targets all applications
                if "All" not in policy.target_resources.get("include", []):
                    continue

                # Check if device filter targets non-corporate devices
                if not self._targets_non_corporate_devices(policy.device_filter):
                    continue

                # Policy meets all criteria
                compliant_policy = policy
                break

            if compliant_policy:
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=compliant_policy
                )
                report.subscription = f"Tenant: {tenant_name}"
                report.status = "PASS"
                report.status_extended = f"Conditional Access Policy '{compliant_policy.name}' enforces sign-in frequency for non-corporate devices."
            else:
                report = Check_Report_Azure(
                    metadata=self.metadata(),
                    resource=conditional_access_policies,
                )
                report.subscription = f"Tenant: {tenant_name}"
                report.resource_name = "Conditional Access Policy"
                report.resource_id = "Conditional Access Policy"
                report.status = "FAIL"
                report.status_extended = "No Conditional Access Policy enforces sign-in frequency for non-corporate devices."

            findings.append(report)

        return findings

    def _targets_non_corporate_devices(self, device_filter) -> bool:
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
        mode = device_filter.mode.lower() if device_filter.mode else ""

        # Include mode: should target non-corporate devices directly
        # Rule pattern: device.trustType -ne "ServerAD" or device.isCompliant -ne True
        if mode == "filtermode.include" or mode == "include":
            # Check for targeting non-compliant OR non-hybrid-joined devices
            targets_non_compliant = (
                "device.iscompliant" in rule and "-ne" in rule and "true" in rule
            )
            targets_non_hybrid = (
                "device.trusttype" in rule and "-ne" in rule and "serverad" in rule
            )
            if targets_non_compliant or targets_non_hybrid:
                return True

        # Exclude mode: should exclude corporate devices (equivalent to targeting non-corporate)
        # Rule pattern: device.trustType -eq "ServerAD" and device.isCompliant -eq True
        elif mode == "filtermode.exclude" or mode == "exclude":
            # Check for excluding compliant AND hybrid-joined devices
            excludes_compliant = (
                "device.iscompliant" in rule and "-eq" in rule and "true" in rule
            )
            excludes_hybrid = (
                "device.trusttype" in rule and "-eq" in rule and "serverad" in rule
            )
            if excludes_compliant or excludes_hybrid:
                return True

        return False
