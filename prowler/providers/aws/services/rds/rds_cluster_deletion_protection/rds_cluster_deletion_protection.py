from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_cluster_deletion_protection(Check):
    def execute(self):
        findings = []
        for db_cluster in rds_client.db_clusters:
            report = Check_Report_AWS(
                metadata=self.metadata(),
                resource=rds_client.db_clusters[db_cluster],
            )
            report.status = "FAIL"
            report.status_extended = f"RDS Cluster {rds_client.db_clusters[db_cluster].id} does not have deletion protection enabled."
            if rds_client.db_clusters[db_cluster].deletion_protection:
                report.status = "PASS"
                report.status_extended = f"RDS Cluster {rds_client.db_clusters[db_cluster].id} has deletion protection enabled."

            findings.append(report)

        return findings
