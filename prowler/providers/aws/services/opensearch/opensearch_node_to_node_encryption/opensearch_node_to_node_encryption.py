from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.opensearch.opensearch_client import opensearch_client

class opensearch_node_to_node_encryption(Check):
    def execute(self):
        findings = []

        for domain in opensearch_client.opensearch_domains:
            report = Check_Report_AWS(self.metadata())
            report.region = domain.region
            report.resource_id = domain.name
            report.resource_arn = domain.arn
            report.resource_tags = domain.tags

            # Check if node-to-node encryption is enabled
            if domain.node_to_node_encryption:
                report.status = "PASS"
                report.status_extended = f"OpenSearch domain {domain.name} has node-to-node encryption enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"OpenSearch domain {domain.name} does not have node-to-node encryption enabled."

            findings.append(report)

        return findings
