from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.vm.vm_client import vm_client


class vm_trusted_launch_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription_name, vms in vm_client.virtual_machines.items():
            for vm_id, vm in vms.items():
                report = Check_Report_Azure(self.metadata())
                report.status = "FAIL"
                report.subscription = subscription_name
                report.resource_name = vm.resource_name
                report.resource_id = vm_id
                report.status_extended = f"VM {vm.resource_name} has trusted launch disabled in subscription {subscription_name}"

                if (
                    vm.security_profile.security_type == "TrustedLaunch"
                    and vm.security_profile.uefi_settings.secure_boot_enabled
                    and vm.security_profile.uefi_settings.v_tpm_enabled
                ):
                    report.status = "PASS"
                    report.status_extended = f"VM {vm.resource_name} has trusted launch enabled in subscription {subscription_name}"

                findings.append(report)

        return findings
