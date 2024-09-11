from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_cluster_integration_cloudwatch_logs(Check):
    def execute(self):
        findings = []
        valid_engines = ["aurora-mysql", "aurora-postgresql", "mysql", "postgres"]
        for db_cluster_arn, db_cluster in rds_client.db_clusters.items():
            if db_cluster.engine in valid_engines:
                report = Check_Report_AWS(self.metadata())
                report.region = db_cluster.region
                report.resource_id = db_cluster.id
                report.resource_arn = db_cluster_arn
                report.resource_tags = db_cluster.tags
                if db_cluster.cloudwatch_logs:
                    report.status = "PASS"
                    report.status_extended = f"RDS Cluster {db_cluster.id} is shipping {', '.join(db_cluster.cloudwatch_logs)} logs to CloudWatch Logs."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"RDS Cluster {db_cluster.id} does not have CloudWatch Logs enabled."

                findings.append(report)

        return findings
