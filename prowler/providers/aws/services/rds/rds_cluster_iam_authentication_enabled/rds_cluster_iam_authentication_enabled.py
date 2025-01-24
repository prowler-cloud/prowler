from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_cluster_iam_authentication_enabled(Check):
    def execute(self):
        findings = []
        for db_cluster in rds_client.db_clusters:
            supported_engines = [
                "postgres",
                "aurora-postgresql",
                "mysql",
                "mariadb",
                "aurora-mysql",
                "aurora",
            ]
            if (
                engine in rds_client.db_clusters[db_cluster].engine
                for engine in supported_engines
            ):
                report = Check_Report_AWS(
                    metadata=self.metadata(),
                    resource=rds_client.db_clusters[db_cluster],
                )

                if rds_client.db_clusters[db_cluster].iam_auth:
                    report.status = "PASS"
                    report.status_extended = f"RDS Cluster {rds_client.db_clusters[db_cluster].id} has IAM authentication enabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"RDS Cluster {rds_client.db_clusters[db_cluster].id} does not have IAM authentication enabled."

                findings.append(report)

        return findings
