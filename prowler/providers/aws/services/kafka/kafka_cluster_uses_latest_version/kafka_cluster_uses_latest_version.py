from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kafka.kafka_client import kafka_client


class kafka_cluster_uses_latest_version(Check):
    def execute(self):
        findings = []

        for cluster in kafka_client.clusters.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=cluster)
            report.status = "PASS"
            report.status_extended = (
                f"Kafka cluster '{cluster.name}' is using the latest version."
            )

            # Serverless clusters don't have specific Kafka versions - AWS manages them automatically
            if cluster.kafka_version == "SERVERLESS":
                report.status = "PASS"
                report.status_extended = f"Kafka cluster '{cluster.name}' is serverless and AWS automatically manages the Kafka version."
            # For provisioned clusters, check if they're using the latest version
            elif cluster.kafka_version != kafka_client.kafka_versions[-1].version:
                report.status = "FAIL"
                report.status_extended = (
                    f"Kafka cluster '{cluster.name}' is not using the latest version."
                )

            findings.append(report)

        return findings
