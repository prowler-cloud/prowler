from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.check.resource_limit import get_resource_scan_limit, limited_findings
from prowler.providers.aws.services.backup.backup_client import backup_client


class backup_recovery_point_encrypted(Check):
    def execute(self):
        def evaluate(recovery_point):
            report = Check_Report_AWS(metadata=self.metadata(), resource=recovery_point)
            report.region = recovery_point.backup_vault_region
            report.status = "FAIL"
            report.status_extended = f"Backup Recovery Point {recovery_point.id} for Backup Vault {recovery_point.backup_vault_name} is not encrypted at rest."
            if recovery_point.encrypted:
                report.status = "PASS"
                report.status_extended = f"Backup Recovery Point {recovery_point.id} for Backup Vault {recovery_point.backup_vault_name} is encrypted at rest."
            return report

        return limited_findings(
            backup_client.iter_recovery_points(),
            evaluate,
            get_resource_scan_limit(
                backup_client.audit_config, "max_backup_recovery_points"
            ),
        )
