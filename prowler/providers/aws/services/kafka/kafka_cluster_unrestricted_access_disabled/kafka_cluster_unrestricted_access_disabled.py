from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kafka.kafka_client import kafka_client


class kafka_cluster_unrestricted_access_disabled(Check):
    def execute(self):
        findings = []

        for cluster in kafka_client.clusters.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=cluster)
            report.status = "FAIL"
            report.status_extended = (
                f"Kafka cluster '{cluster.name}' has unrestricted access enabled."
            )

            # Serverless clusters always require authentication by default
            if cluster.kafka_version == "SERVERLESS":
                report.status = "PASS"
                report.status_extended = f"Kafka cluster '{cluster.name}' is serverless and always requires authentication by default."
            # For provisioned clusters, check the unauthenticated access configuration
            elif not cluster.unauthentication_access:
                report.status = "PASS"
                report.status_extended = f"Kafka cluster '{cluster.name}' does not have unrestricted access enabled."

            findings.append(report)

        return findings
