from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.opensearch.opensearch_client import (
    opensearch_client,
)


class opensearch_service_domains_fault_tolerant_data_nodes(Check):
    def execute(self):
        findings = []

        for domain in opensearch_client.opensearch_domains.values():
            report = Check_Report_AWS(self.metadata())
            report.region = domain.region
            report.resource_id = domain.name
            report.resource_arn = domain.arn
            report.resource_tags = domain.tags

            report.status = "FAIL"
            report.status_extended = f"Opensearch domain {domain.name} is not fault tolerant as it has less than 3 data nodes and cross-zone replication (Zone Awareness) is not enabled."

            if domain.instance_count >= 3 and domain.zone_awareness_enabled:
                report.status = "PASS"
                report.status_extended = f"Opensearch domain {domain.name} is fault tolerant with {domain.instance_count} data nodes and cross-zone replication (Zone Awareness) enabled."
            elif domain.instance_count >= 3 and not domain.zone_awareness_enabled:
                report.status = "FAIL"
                report.status_extended = f"Opensearch domain {domain.name} is not fault tolerant as it has {domain.instance_count} data nodes, but cross-zone replication (Zone Awareness) is not enabled."
            elif domain.instance_count < 3 and domain.zone_awareness_enabled:
                report.status = "FAIL"
                report.status_extended = f"Opensearch domain {domain.name} is not fault tolerant as it has cross-zone replication (Zone Awareness) enabled, but only {domain.instance_count} data nodes."

            findings.append(report)

        return findings
