from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_aurora_mysql_integration_cloudwatch_logs(Check):
    def execute(self):
        findings = []
        for db_cluster_arn, db_cluster in rds_client.db_clusters.items():
            if db_cluster.engine == "aurora-mysql":
                report = Check_Report_AWS(self.metadata())
                report.region = db_cluster.region
                report.resource_id = db_cluster.id
                report.resource_arn = db_cluster_arn
                report.resource_tags = db_cluster.tags
                if db_cluster.cloudwatch_logs:
                    report.status = "PASS"
                    report.status_extended = f"Aurora MySQL Cluster {db_cluster.id} is shipping {' '.join(db_cluster.cloudwatch_logs)} to CloudWatch Logs."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Aurora MySQL Cluster {db_cluster.id} does not have CloudWatch Logs enabled."

                findings.append(report)

        return findings
