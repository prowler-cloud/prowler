from prowler.lib.check.models import Check, Check_Report_AWS, Severity
from prowler.providers.aws.services.documentdb.documentdb_client import (
    documentdb_client,
)


class documentdb_cluster_backup_enabled(Check):
    def execute(self):
        findings = []
        for cluster in documentdb_client.db_clusters.values():
            report = Check_Report_AWS(self.metadata())
            report.region = cluster.region
            report.resource_id = cluster.id
            report.resource_arn = cluster.arn
            report.resource_tags = cluster.tags
            report.status = "FAIL"
            report.status_extended = (
                f"DocumentDB Cluster {cluster.id} does not have backup enabled."
            )
            if cluster.backup_retention_period >= documentdb_client.audit_config.get(
                "minimum_backup_retention_period", 7
            ):
                report.status = "PASS"
                report.status_extended = f"DocumentDB Cluster {cluster.id} has backup enabled with retention period {cluster.backup_retention_period} days."
            else:
                if cluster.backup_retention_period > 0:
                    report.status = "FAIL"
                    report.check_metadata.Severity = Severity.low
                    report.status_extended = f"DocumentDB Cluster {cluster.id} has backup enabled with retention period {cluster.backup_retention_period} days. Recommended to increase the backup retention period to a minimum of 7 days."

            findings.append(report)

        return findings
