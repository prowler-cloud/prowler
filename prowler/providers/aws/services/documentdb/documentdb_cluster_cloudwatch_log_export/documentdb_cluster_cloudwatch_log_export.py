from prowler.lib.check.models import Check, Check_Report_AWS, Severity
from prowler.providers.aws.services.documentdb.documentdb_client import (
    documentdb_client,
)


class documentdb_cluster_cloudwatch_log_export(Check):
    def execute(self):
        findings = []
        for cluster in documentdb_client.db_clusters.values():
            report = Check_Report_AWS(self.metadata())
            report.region = cluster.region
            report.resource_id = cluster.id
            report.resource_arn = cluster.arn
            report.resource_tags = cluster.tags
            report.status = "FAIL"
            report.status_extended = f"DocumentDB Cluster {cluster.id} does not have cloudwatch log export enabled."
            if cluster.cloudwatch_logs:
                if (
                    "audit" in cluster.cloudwatch_logs
                    and "profiler" in cluster.cloudwatch_logs
                ):
                    report.status = "PASS"
                    report.status_extended = f"DocumentDB Cluster {cluster.id} is shipping {' '.join(cluster.cloudwatch_logs)} to CloudWatch Logs."
                elif (
                    "audit" in cluster.cloudwatch_logs
                    or "profiler" in cluster.cloudwatch_logs
                ):
                    report.status = "FAIL"
                    report.check_metadata.Severity = Severity.low
                    report.status_extended = f"DocumentDB Cluster {cluster.id} is only shipping {' '.join(cluster.cloudwatch_logs)} to CloudWatch Logs. Recommended to ship both Audit and Profiler logs."

            findings.append(report)

        return findings
