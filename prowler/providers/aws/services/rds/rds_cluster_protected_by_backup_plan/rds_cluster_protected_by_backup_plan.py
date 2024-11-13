from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.backup.backup_client import backup_client
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_cluster_protected_by_backup_plan(Check):
    def execute(self):
        findings = []
        for db_cluster_arn, db_cluster in rds_client.db_clusters.items():
            report = Check_Report_AWS(self.metadata())
            report.region = db_cluster.region
            report.resource_id = db_cluster.id
            report.resource_arn = db_cluster_arn
            report.resource_tags = db_cluster.tags
            report.status = "FAIL"
            report.status_extended = (
                f"RDS Cluster {db_cluster.id} is not protected by a backup plan."
            )

            if (
                db_cluster_arn in backup_client.protected_resources
                or f"arn:{rds_client.audited_partition}:rds:*:*:cluster:*"
                in backup_client.protected_resources
                or "*" in backup_client.protected_resources
            ):
                report.status = "PASS"
                report.status_extended = (
                    f"RDS Cluster {db_cluster.id} is protected by a backup plan."
                )

            findings.append(report)

        return findings
