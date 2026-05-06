from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.recovery.recovery_client import recovery_client

MINIMUM_RETENTION_DAYS = 30


class recovery_vault_backup_policy_retention_adequate(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription_name, vaults in recovery_client.vaults.items():
            for vault_id, vault in vaults.items():
                if not vault.backup_policies:
                    report = Check_Report_Azure(
                        metadata=self.metadata(), resource=vault
                    )
                    report.subscription = subscription_name
                    report.resource_name = vault.name
                    report.resource_id = vault.id
                    report.location = vault.location
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Recovery vault '{vault.name}' has no backup "
                        f"policies configured."
                    )
                    findings.append(report)
                    continue

                for policy_id, policy in vault.backup_policies.items():
                    report = Check_Report_Azure(
                        metadata=self.metadata(), resource=vault
                    )
                    report.subscription = subscription_name
                    report.resource_name = f"{vault.name}/{policy.name}"
                    report.resource_id = policy.id
                    report.location = vault.location

                    if policy.retention_days is None:
                        report.status = "FAIL"
                        report.status_extended = (
                            f"Backup policy '{policy.name}' in vault "
                            f"'{vault.name}' has no daily retention configured."
                        )
                    elif policy.retention_days < MINIMUM_RETENTION_DAYS:
                        report.status = "FAIL"
                        report.status_extended = (
                            f"Backup policy '{policy.name}' in vault "
                            f"'{vault.name}' has {policy.retention_days}-day "
                            f"retention (minimum: {MINIMUM_RETENTION_DAYS})."
                        )
                    else:
                        report.status = "PASS"
                        report.status_extended = (
                            f"Backup policy '{policy.name}' in vault "
                            f"'{vault.name}' has {policy.retention_days}-day "
                            f"retention."
                        )

                    findings.append(report)

        return findings
