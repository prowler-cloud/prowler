from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kafka.kafka_client import kafka_client


class kafka_cluster_enhanced_monitoring_enabled(Check):
    def execute(self):
        findings = []

        for cluster in kafka_client.clusters.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=cluster)
            report.status = "PASS"
            report.status_extended = (
                f"Kafka cluster '{cluster.name}' has enhanced monitoring enabled."
            )

            # Serverless clusters always have enhanced monitoring enabled by default
            if cluster.kafka_version == "SERVERLESS":
                report.status = "PASS"
                report.status_extended = f"Kafka cluster '{cluster.name}' is serverless and always has enhanced monitoring enabled by default."
            # For provisioned clusters, check the enhanced monitoring configuration
            elif cluster.enhanced_monitoring == "DEFAULT":
                report.status = "FAIL"
                report.status_extended = f"Kafka cluster '{cluster.name}' does not have enhanced monitoring enabled."

            findings.append(report)

        return findings
