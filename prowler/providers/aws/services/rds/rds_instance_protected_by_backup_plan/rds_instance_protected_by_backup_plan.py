from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.backup.backup_client import backup_client
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_protected_by_backup_plan(Check):
    def execute(self):
        findings = []
        for db_instance_arn, db_instance in rds_client.db_instances.items():
            # Makes sure the instance is not running with an Aurora engine
            # Aurora backup plans require enabling it seperatly from RDS
            if db_instance.engine not in [
                "aurora-mysql",
                "aurora",
                "aurora-postgresql",
            ]:
                report = Check_Report_AWS(self.metadata())
                report.region = db_instance.region
                report.resource_id = db_instance.id
                report.resource_arn = db_instance_arn
                report.resource_tags = db_instance.tags
                report.status = "FAIL"
                report.status_extended = (
                    f"RDS Instance {db_instance.id} is not protected by a backup plan."
                )

                if (
                    db_instance_arn in backup_client.protected_resources
                    or f"arn:{rds_client.audited_partition}:rds:*:*:instance:*"
                    in backup_client.protected_resources
                    or "*" in backup_client.protected_resources
                ):
                    report.status = "PASS"
                    report.status_extended = (
                        f"RDS Instance {db_instance.id} is protected by a backup plan."
                    )

                findings.append(report)

        for db_cluster in rds_client.db_clusters:
            if rds_client.db_clusters[db_cluster].engine in [
                "aurora-mysql",
                "aurora",
                "aurora-postgresql",
            ]:
                report = Check_Report_AWS(self.metadata())
                report.region = rds_client.db_clusters[db_cluster].region
                report.resource_id = rds_client.db_clusters[db_cluster].id
                report.resource_arn = db_cluster
                report.resource_tags = rds_client.db_clusters[db_cluster].tags
                report.status = "FAIL"
                report.status_extended = f"RDS Cluster {rds_client.db_clusters[db_cluster].id} is not protected by a backup plan."
                if (
                    db_cluster in backup_client.protected_resources
                    or f"arn:{rds_client.audited_partition}:rds:*:*:cluster:*"
                    in backup_client.protected_resources
                    or "*" in backup_client.protected_resources
                ):
                    report.status = "PASS"
                    report.status_extended = f"RDS Cluster {rds_client.db_clusters[db_cluster].id} is protected by a backup plan."
                findings.append(report)

        return findings
