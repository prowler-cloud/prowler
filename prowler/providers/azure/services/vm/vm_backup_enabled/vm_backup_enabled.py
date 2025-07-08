from azure.mgmt.recoveryservicesbackup.activestamp.models import DataSourceType

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.recovery.recovery_client import recovery_client
from prowler.providers.azure.services.vm.vm_client import vm_client


class vm_backup_enabled(Check):
    """
    Ensure that Microsoft Azure Backup service is in use for your Azure virtual machines (VMs).

    This check evaluates whether each Azure VM in the subscription is protected by Azure Backup.

    - PASS: The VM is protected by Azure Backup (present in a Recovery Services vault).
    - FAIL: The VM is not protected by Azure Backup (not present in any Recovery Services vault).
    """

    def execute(self) -> list[Check_Report_Azure]:
        """Execute Azure VM backup enabled check.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        for subscription_name, vms in vm_client.virtual_machines.items():
            vaults = recovery_client.vaults.get(subscription_name, {})
            for vm in vms.values():
                found = False
                found_vault_name = None
                for vault in vaults.values():
                    for backup_item in vault.backup_protected_items.values():
                        if (
                            backup_item.workload_type == DataSourceType.VM
                            and backup_item.name.split(";")[-1] == vm.resource_name
                        ):
                            found = True
                            found_vault_name = vault.name
                            break
                    if found:
                        break
                report = Check_Report_Azure(metadata=self.metadata(), resource=vm)
                report.subscription = subscription_name
                if found:
                    report.status = "PASS"
                    report.status_extended = f"VM {vm.resource_name} in subscription {subscription_name} is protected by Azure Backup (vault: {found_vault_name})."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"VM {vm.resource_name} in subscription {subscription_name} is not protected by Azure Backup."
                findings.append(report)
        return findings
