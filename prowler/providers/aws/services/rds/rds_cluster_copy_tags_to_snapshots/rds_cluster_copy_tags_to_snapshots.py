from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_cluster_copy_tags_to_snapshots(Check):
    def execute(self):
        findings = []
        for db_cluster in rds_client.db_clusters.values():
            report = Check_Report_AWS(
                metadata=self.metadata(), resource_metadata=db_cluster
            )
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
