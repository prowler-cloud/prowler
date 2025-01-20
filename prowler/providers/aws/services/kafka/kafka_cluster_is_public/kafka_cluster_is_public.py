from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kafka.kafka_client import kafka_client


class kafka_cluster_is_public(Check):
    def execute(self):
        findings = []

        for cluster in kafka_client.clusters.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=cluster)
            report.status = "FAIL"
            report.status_extended = (
                f"Kafka cluster '{cluster.name}' is publicly accessible."
            )

            if cluster.public_access:
                report.status = "PASS"
                report.status_extended = (
                    f"Kafka cluster '{cluster.name}' is not publicly accessible."
                )

            findings.append(report)

        return findings
