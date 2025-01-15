from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_cluster_integration_cloudwatch_logs(Check):
    def execute(self):
        findings = []
        valid_engines = ["aurora-mysql", "aurora-postgresql", "mysql", "postgres"]
        for db_cluster in rds_client.db_clusters.values():
            if db_cluster.engine in valid_engines:
                report = Check_Report_AWS(
                    metadata=self.metadata(), resource_metadata=db_cluster
                )
                if db_cluster.cloudwatch_logs:
                    report.status = "PASS"
                    report.status_extended = f"RDS Cluster {db_cluster.id} is shipping {', '.join(db_cluster.cloudwatch_logs)} logs to CloudWatch Logs."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"RDS Cluster {db_cluster.id} does not have CloudWatch Logs enabled."

                findings.append(report)

        return findings
