from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_cluster_default_admin(Check):
    def execute(self):
        findings = []
        for db_cluster in rds_client.db_clusters:
            report = Check_Report_AWS(self.metadata())
            report.region = rds_client.db_clusters[db_cluster].region
            report.resource_id = rds_client.db_clusters[db_cluster].id
            report.resource_arn = db_cluster
            report.resource_tags = rds_client.db_clusters[db_cluster].tags
            report.status = "FAIL"
            report.status_extended = f"RDS Cluster {rds_client.db_clusters[db_cluster].id} is using the default master username."
            if rds_client.db_clusters[db_cluster].username not in [
                "admin",
                "postgres",
            ]:
                report.status = "PASS"
                report.status_extended = f"RDS Cluster {rds_client.db_clusters[db_cluster].id} is not using the default master username."

            findings.append(report)

        return findings
