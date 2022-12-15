from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.opensearch.opensearch_client import (
    opensearch_client,
)


class opensearch_service_domains_audit_logging_enabled(Check):
    def execute(self):
        findings = []
        for domain in opensearch_client.opensearch_domains:
            report = Check_Report_AWS(self.metadata())
            report.region = domain.region
            report.resource_id = domain.name
            report.resource_arn = domain.arn
            report.status = "FAIL"
            report.status_extended = (
                f"Opensearch domain {domain.name} AUDIT_LOGS disabled"
            )
            for logging_item in domain.logging:
                if logging_item.name == "AUDIT_LOGS" and logging_item.enabled:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Opensearch domain {domain.name} AUDIT_LOGS enabled"
                    )

            findings.append(report)

        return findings
