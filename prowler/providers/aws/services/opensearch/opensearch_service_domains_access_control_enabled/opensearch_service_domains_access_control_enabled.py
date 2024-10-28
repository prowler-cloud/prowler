from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.opensearch.opensearch_client import (
    opensearch_client,
)


class opensearch_service_domains_access_control_enabled(Check):
    def execute(self):
        findings = []
        for domain in opensearch_client.opensearch_domains.values():
            report = Check_Report_AWS(self.metadata())
            report.region = domain.region
            report.resource_id = domain.name
            report.resource_arn = domain.arn
            report.resource_tags = domain.tags
            report.status = "FAIL"
            report.status_extended = f"Opensearch domain {domain.name} does not have fine grained access control enabled."
            if domain.advanced_settings_enabled:
                report.status = "PASS"
                report.status_extended = f"Opensearch domain {domain.name} has fine grained access control enabled."

            findings.append(report)

        return findings
