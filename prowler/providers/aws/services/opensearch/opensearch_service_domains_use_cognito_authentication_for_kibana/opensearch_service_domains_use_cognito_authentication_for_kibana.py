from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.opensearch.opensearch_client import (
    opensearch_client,
)


class opensearch_service_domains_use_cognito_authentication_for_kibana(Check):
    def execute(self):
        findings = []
        for domain in opensearch_client.opensearch_domains:
            report = Check_Report_AWS(self.metadata())
            report.region = domain.region
            report.resource_id = domain.name
            report.resource_arn = domain.arn
            report.status = "PASS"
            report.status_extended = f"Opensearch domain {domain.name} has Amazon Cognito authentication for Kibana enabled"
            if not domain.cognito_options:
                report.status = "FAIL"
                report.status_extended = f"Opensearch domain {domain.name} does not have Amazon Cognito authentication for Kibana enabled"

            findings.append(report)

        return findings
