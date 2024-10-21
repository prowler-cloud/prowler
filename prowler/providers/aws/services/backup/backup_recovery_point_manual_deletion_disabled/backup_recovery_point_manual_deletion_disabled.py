from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.backup.backup_client import backup_client
import json

class backup_recovery_point_manual_deletion_disabled(Check):
    def execute(self):
        findings = []

        for backup_vault in backup_client.backup_vaults:
            report = Check_Report_AWS(self.metadata())
            report.region = backup_vault.region
            report.resource_id = backup_vault.name
            report.resource_arn = backup_vault.arn

            try:
                policy_response = backup_client.get_backup_vault_access_policy(BackupVaultName=backup_vault.name)
                policy = policy_response.get('Policy', '{}')
                policy_doc = json.loads(policy)

                deny_deletion = False
                for statement in policy_doc.get('Statement', []):
                    if statement.get('Effect') == 'Deny' and 'backup:DeleteRecoveryPoint' in statement.get('Action', []):
                        deny_deletion = True
                        break

                if deny_deletion:
                    report.status = "PASS"
                    report.status_extended = f"Backup vault '{backup_vault.name}' prevents manual deletion of recovery points."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Backup vault '{backup_vault.name}' does not prevent manual deletion of recovery points."

            except Exception as error:
                report.status = "FAIL"
                report.status_extended = f"Error retrieving policy for backup vault '{backup_vault.name}': {error}"

            findings.append(report)

        return findings
