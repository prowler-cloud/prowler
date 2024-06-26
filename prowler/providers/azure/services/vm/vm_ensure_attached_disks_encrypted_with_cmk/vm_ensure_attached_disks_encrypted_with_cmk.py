from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.vm.vm_client import vm_client


class vm_ensure_attached_disks_encrypted_with_cmk(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription_name, disks in vm_client.disks.items():
            for disk_id, disk in disks.items():
                if disk.vms_attached:
                    report = Check_Report_Azure(self.metadata())
                    report.status = "PASS"
                    report.subscription = subscription_name
                    report.resource_name = disk.resource_name
                    report.resource_id = disk.resource_id
                    report.location = disk.location
                    report.status_extended = f"Disk '{disk_id}' is encrypted with a customer-managed key in subscription {subscription_name}."

                    if (
                        not disk.encryption_type
                        or disk.encryption_type == "EncryptionAtRestWithPlatformKey"
                    ):
                        report.status = "FAIL"
                        report.status_extended = f"Disk '{disk_id}' is not encrypted with a customer-managed key in subscription {subscription_name}."

                    findings.append(report)

        return findings
