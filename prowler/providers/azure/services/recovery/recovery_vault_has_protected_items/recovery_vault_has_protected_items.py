from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.recovery.recovery_client import recovery_client


class recovery_vault_has_protected_items(Check):
    def execute(self) -> list[Check_Report_Azure]:
        findings = []

        for subscription_name, vaults in recovery_client.vaults.items():
            for vault in vaults.values():
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=vault
                )
                report.subscription = subscription_name
                report.resource_name = vault.name
                report.resource_id = vault.id
                report.location = vault.location

                if vault.backup_protected_items:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Recovery Services vault '{vault.name}' has "
                        f"{len(vault.backup_protected_items)} protected items."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Recovery Services vault '{vault.name}' has no "
                        f"protected items configured."
                    )

                findings.append(report)

        return findings
