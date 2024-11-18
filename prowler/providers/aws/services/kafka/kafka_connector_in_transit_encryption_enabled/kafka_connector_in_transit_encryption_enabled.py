from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kafka.kafkaconnect_client import kafkaconnect_client


class kafka_connector_in_transit_encryption_enabled(Check):
    def execute(self):
        findings = []

        for arn_connector, connector in kafkaconnect_client.connectors.items():
            report = Check_Report_AWS(self.metadata())
            report.region = connector.region
            report.resource_id = connector.name
            report.resource_arn = arn_connector
            report.status = "FAIL"
            report.status_extended = f"Kafka connector {connector.name} does not have encryption in transit enabled."

            if connector.encryption_in_transit == "TLS":
                report.status = "PASS"
                report.status_extended = f"Kafka connector {connector.name} has encryption in transit enabled."

            findings.append(report)

        return findings
