from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kafka.kafka_client import kafka_client


class kafka_cluster_enhanced_monitoring_enabled(Check):
    def execute(self):
        findings = []

        for arn_cluster, cluster in kafka_client.clusters.items():
            report = Check_Report_AWS(self.metadata())
            report.region = cluster.region
            report.resource_id = cluster.id
            report.resource_arn = arn_cluster
            report.resource_tags = cluster.tags
            report.status = "PASS"
            report.status_extended = (
                f"Kafka cluster '{cluster.name}' has enhanced monitoring enabled."
            )

            if cluster.enhanced_monitoring == "DEFAULT":
                report.status = "FAIL"
                report.status_extended = f"Kafka cluster '{cluster.name}' does not have enhanced monitoring enabled."

            findings.append(report)

        return findings
