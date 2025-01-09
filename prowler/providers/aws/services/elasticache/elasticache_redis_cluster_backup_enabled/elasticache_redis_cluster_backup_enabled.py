from prowler.lib.check.models import Check, Check_Report_AWS, Severity
from prowler.providers.aws.services.elasticache.elasticache_client import (
    elasticache_client,
)


class elasticache_redis_cluster_backup_enabled(Check):
    def execute(self):
        findings = []
        for repl_group in elasticache_client.replication_groups.values():
            report = Check_Report_AWS(self.metadata())
            report.region = repl_group.region
            report.resource_id = repl_group.id
            report.resource_arn = repl_group.arn
            report.resource_tags = repl_group.tags
            report.status = "FAIL"
            report.status_extended = f"Elasticache Redis cache cluster {repl_group.id} does not have automated snapshot backups enabled."
            if repl_group.snapshot_retention > elasticache_client.audit_config.get(
                "minimum_snapshot_retention_period", 7
            ):
                report.status = "PASS"
                report.status_extended = f"Elasticache Redis cache cluster {repl_group.id} has automated snapshot backups enabled with retention period {repl_group.snapshot_retention} days."
            else:
                if repl_group.snapshot_retention > 0:
                    report.status = "FAIL"
                    report.check_metadata.Severity = Severity.low
                    report.status_extended = f"Elasticache Redis cache cluster {repl_group.id} has automated snapshot backups enabled with retention period {repl_group.snapshot_retention} days. Recommended to increase the snapshot retention period to a minimum of 7 days."

            findings.append(report)

        return findings
