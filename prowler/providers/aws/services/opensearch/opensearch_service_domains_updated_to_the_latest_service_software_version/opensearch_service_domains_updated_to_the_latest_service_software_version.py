from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.opensearch.opensearch_client import (
    opensearch_client,
)


class opensearch_service_domains_updated_to_the_latest_service_software_version(Check):
    def execute(self):
        findings = []
        for domain in opensearch_client.opensearch_domains:
            report = Check_Report_AWS(self.metadata())
            report.region = domain.region
            report.resource_id = domain.name
            report.resource_arn = domain.arn
            report.status = "PASS"
            report.status_extended = f"Opensearch domain {domain.name}  with version {domain.version} does not have internal updates available"
            if domain.update_available:
                report.status = "FAIL"
                report.status_extended = f"Opensearch domain {domain.name} with version {domain.version} has internal updates available"

            findings.append(report)

        return findings
