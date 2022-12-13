from prowler.lib.check.models import Check, Check_Report
from prowler.providers.aws.services.opensearch.opensearch_client import (
    opensearch_client,
)


class opensearch_service_domains_node_to_node_encryption_enabled(Check):
    def execute(self):
        findings = []
        for domain in opensearch_client.opensearch_domains:
            report = Check_Report(self.metadata())
            report.region = domain.region
            report.resource_id = domain.name
            report.resource_arn = domain.arn
            report.status = "PASS"
            report.status_extended = (
                f"Opensearch domain {domain.name} has node-to-node encryption enabled"
            )
            if not domain.node_to_node_encryption:
                report.status = "FAIL"
                report.status_extended = f"Opensearch domain {domain.name} does not have node-to-node encryption enabled"

            findings.append(report)

        return findings
