from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kafka.kafka_client import kafka_client


class kafka_cluster_in_transit_encryption_enabled(Check):
    def execute(self):
        findings = []

        for cluster in kafka_client.clusters.values():
            report = Check_Report_AWS(
                metadata=self.metadata(), resource_metadata=cluster
            )
            report.status = "FAIL"
            report.status_extended = f"Kafka cluster '{cluster.name}' does not have encryption in transit enabled."

            if (
                cluster.encryption_in_transit.client_broker == "TLS"
                and cluster.encryption_in_transit.in_cluster
            ):
                report.status = "PASS"
                report.status_extended = (
                    f"Kafka cluster '{cluster.name}' has encryption in transit enabled."
                )

            findings.append(report)

        return findings
