from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kafka.kafka_client import kafka_client


class kafka_cluster_uses_latest_version(Check):
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
                f"Kafka cluster '{cluster.name}' is using the latest version."
            )

            if cluster.kafka_version != kafka_client.kafka_versions[-1].version:
                report.status = "FAIL"
                report.status_extended = (
                    f"Kafka cluster '{cluster.name}' is not using the latest version."
                )

            findings.append(report)

        return findings
