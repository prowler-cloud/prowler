from azure.mgmt.recoveryservicesbackup.activestamp.models import DataSourceType

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.recovery.recovery_client import recovery_client
from prowler.providers.azure.services.vm.vm_client import vm_client


class vm_sufficient_daily_backup_retention_period(Check):
    """
    Ensure there is a sufficient daily backup retention period configured for Azure virtual machines.
    - PASS: The VM has a backup policy with sufficient daily retention period.
    - FAIL: The VM does not have a backup policy or the retention period is insufficient.
    """

    def execute(self) -> list[Check_Report_Azure]:
        findings = []
        min_retention_days = getattr(vm_client, "audit_config", {}).get(
            "vm_backup_min_daily_retention_days", 7
        )

        for subscription, vms in vm_client.virtual_machines.items():
            vaults = recovery_client.vaults.get(subscription, {})
            for vm in vms.values():
                backup_found = False
                retention_days = None
                for vault in vaults.values():
                    for backup_item in vault.backup_protected_items.values():
                        if (
                            backup_item.workload_type == DataSourceType.VM
                            and backup_item.name.split(";")[-1] == vm.resource_name
                        ):
                            backup_found = True
                            policy_id = backup_item.backup_policy_id
                            if policy_id and policy_id in vault.backup_policies:
                                retention_days = vault.backup_policies[
                                    policy_id
                                ].retention_days
                            break
                    if backup_found:
                        break
                if backup_found and retention_days:
                    report = Check_Report_Azure(metadata=self.metadata(), resource=vm)
                    report.subscription = subscription
                    if retention_days >= min_retention_days:
                        report.status = "PASS"
                        report.status_extended = f"VM {vm.resource_name} in subscription {subscription} has a daily backup retention period of {retention_days} days (minimum required: {min_retention_days})."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"VM {vm.resource_name} in subscription {subscription} has insufficient daily backup retention period of {retention_days} days (minimum required: {min_retention_days})."
                    findings.append(report)
        return findings
