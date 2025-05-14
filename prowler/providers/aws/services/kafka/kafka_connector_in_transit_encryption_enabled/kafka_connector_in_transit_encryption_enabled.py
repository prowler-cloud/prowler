from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kafka.kafkaconnect_client import kafkaconnect_client


class kafka_connector_in_transit_encryption_enabled(Check):
    def execute(self):
        findings = []

        for connector in kafkaconnect_client.connectors.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=connector)
            report.status = "FAIL"
            report.status_extended = f"Kafka connector {connector.name} does not have encryption in transit enabled."

            if connector.encryption_in_transit == "TLS":
                report.status = "PASS"
                report.status_extended = f"Kafka connector {connector.name} has encryption in transit enabled."

            findings.append(report)

        return findings
