from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kafka.kafka_client import kafka_client


class kafka_cluster_mutual_tls_authentication_enabled(Check):
    def execute(self):
        findings = []

        for cluster in kafka_client.clusters.values():
            report = Check_Report_AWS(
                metadata=self.metadata(), resource_metadata=cluster
            )
            report.status = "FAIL"
            report.status_extended = f"Kafka cluster '{cluster.name}' does not have mutual TLS authentication enabled."

            if cluster.tls_authentication:
                report.status = "PASS"
                report.status_extended = f"Kafka cluster '{cluster.name}' has mutual TLS authentication enabled."

            findings.append(report)

        return findings
