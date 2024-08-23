from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_cluster_copy_tags_to_snapshots(Check):
    def execute(self):
        findings = []
        for db_cluster_arn, db_cluster in rds_client.db_clusters.items():
            report = Check_Report_AWS(self.metadata())
            report.region = db_cluster.region
            report.resource_id = db_cluster.id
            report.resource_arn = db_cluster_arn
            report.resource_tags = db_cluster.tags
            if db_cluster.copy_tags_to_snapshot:
                report.status = "PASS"
                report.status_extended = (
                    f"RDS Cluster {db_cluster.id} has copy tags to snapshots enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"RDS Cluster {db_cluster.id} does not have copy tags to snapshots enabled."

            findings.append(report)

        return findings
