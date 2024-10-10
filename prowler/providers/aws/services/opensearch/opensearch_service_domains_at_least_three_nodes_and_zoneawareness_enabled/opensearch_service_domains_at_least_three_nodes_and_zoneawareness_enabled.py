from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.opensearch.opensearch_client import (
    opensearch_client,
)


class opensearch_service_domains_at_least_three_nodes_and_zoneawareness_enabled(Check):
    def execute(self):
        findings = []

        for domain in opensearch_client.opensearch_domains.values():
            report = Check_Report_AWS(self.metadata())
            report.region = domain.region
            report.resource_id = domain.name
            report.resource_arn = domain.arn
            report.resource_tags = domain.tags

            report.status = "FAIL"
            report.status_extended = f"Opensearch domain {domain.name} does not meet the requirements: it has less than 3 data nodes and zone awareness is not enabled."

            if domain.instance_count >= 3 and domain.zone_awareness_enabled:
                report.status = "PASS"
                report.status_extended = f"Opensearch domain {domain.name} has {domain.instance_count} data nodes and zone awareness enabled."
            elif domain.instance_count >= 3 and not domain.zone_awareness_enabled:
                report.status = "FAIL"
                report.status_extended = f"Opensearch domain {domain.name} has {domain.instance_count} data nodes, but zone awareness is not enabled."
            elif domain.instance_count < 3 and domain.zone_awareness_enabled:
                report.status = "FAIL"
                report.status_extended = f"Opensearch domain {domain.name} has zone awareness enabled, but only {domain.instance_count} data nodes."

            findings.append(report)

        return findings
