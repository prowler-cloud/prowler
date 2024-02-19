from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.vm.vm_client import vm_client


class vm_ensure_using_managed_disks(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription_name, vms in vm_client.virtual_machines.items():
            for vm_id, vm in vms.items():
                report = Check_Report_Azure(self.metadata())
                report.status = "PASS"
                report.subscription = subscription_name
                report.resource_name = vm.resource_name
                report.resource_id = vm_id
                report.status_extended = f"VM {vm.resource_name} is using managed disks in subscription {subscription_name}"

                using_managed_disks = (
                    True if vm.storage_profile.os_disk.managed_disk else False
                )

                for data_disk in vm.storage_profile.data_disks:
                    if not data_disk.managed_disk:
                        using_managed_disks = False
                        break

                if not using_managed_disks:
                    report.status = "FAIL"
                    report.status_extended = f"VM {vm.resource_name} is not using managed disks in subscription {subscription_name}"

                findings.append(report)

        return findings
