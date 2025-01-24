from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kafka.kafka_client import kafka_client
from prowler.providers.aws.services.kms.kms_client import kms_client


class kafka_cluster_encryption_at_rest_uses_cmk(Check):
    def execute(self):
        findings = []

        for cluster in kafka_client.clusters.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=cluster)
            report.status = "FAIL"
            report.status_extended = f"Kafka cluster '{cluster.name}' does not have encryption at rest enabled with a CMK."

            if any(
                (
                    cluster.data_volume_kms_key_id == key.arn
                    and getattr(key, "manager", "") == "CUSTOMER"
                )
                for key in kms_client.keys
            ):
                report.status = "PASS"
                report.status_extended = f"Kafka cluster '{cluster.name}' has encryption at rest enabled with a CMK."

            findings.append(report)

        return findings
