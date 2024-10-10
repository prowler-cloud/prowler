from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.opensearch.opensearch_client import (
    opensearch_client,
)


class opensearch_service_domains_at_least_three_master_nodes(Check):
    def execute(self):
        findings = []

        for domain in opensearch_client.opensearch_domains.values():
            report = Check_Report_AWS(self.metadata())
            report.region = domain.region
            report.resource_id = domain.name
            report.resource_arn = domain.arn
            report.resource_tags = domain.tags

            report.status = "FAIL"
            report.status_extended = f"Opensearch domain {domain.name} has only {domain.dedicated_master_count} master nodes."

            if domain.dedicated_master_count >= 3:
                report.status = "PASS"
                report.status_extended = f"Opensearch domain {domain.name} has {domain.dedicated_master_count} master nodes."

            findings.append(report)

        return findings
