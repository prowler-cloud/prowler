from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.opensearch.opensearch_client import (
    opensearch_client,
)


class opensearch_domain_data_nodes_fault_tolerant(Check):
    def execute(self):
        findings = []
        for domain in opensearch_client.opensearch_domains:
            report = Check_Report_AWS(self.metadata())
            report.resource_id = domain.name
            report.resource_arn = domain.arn
            report.region = domain.region
            report.resource_tags = domain.tags
            report.status = "PASS"
            report.status_extended = f"Opensearch domain {domain.name} has {domain.data_nodes_count} data nodes."

            if domain.data_nodes_count < 3:
                report.status = "FAIL"
                report.status_extended = f"Opensearch domain {domain.name} does not have at least 3 data nodes, which is recommended for fault tolerance."

            findings.append(report)

        return findings
