from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.opensearch.opensearch_client import (
    opensearch_client,
)


class opensearch_service_domains_cloudwatch_logging_enabled(Check):
    def execute(self):
        findings = []
        for domain in opensearch_client.opensearch_domains:
            report = Check_Report_AWS(self.metadata())
            report.region = domain.region
            report.resource_id = domain.name
            report.resource_arn = domain.arn
            report.status = "FAIL"
            report.status_extended = f"Opensearch domain {domain.name} SEARCH_SLOW_LOGS and INDEX_SLOW_LOGS disabled"
            has_SEARCH_SLOW_LOGS = False
            has_INDEX_SLOW_LOGS = False
            for logging_item in domain.logging:
                if logging_item.name == "SEARCH_SLOW_LOGS" and logging_item.enabled:
                    has_SEARCH_SLOW_LOGS = True
                if logging_item.name == "INDEX_SLOW_LOGS" and logging_item.enabled:
                    has_INDEX_SLOW_LOGS = True

            if has_SEARCH_SLOW_LOGS and has_INDEX_SLOW_LOGS:
                report.status = "PASS"
                report.status_extended = f"Opensearch domain {domain.name} SEARCH_SLOW_LOGS and INDEX_SLOW_LOGS enabled"
            elif not has_SEARCH_SLOW_LOGS and has_INDEX_SLOW_LOGS:
                report.status = "FAIL"
                report.status_extended = f"Opensearch domain {domain.name} INDEX_SLOW_LOGS enabled but SEARCH_SLOW_LOGS disabled"
            elif not has_INDEX_SLOW_LOGS and has_SEARCH_SLOW_LOGS:
                report.status = "FAIL"
                report.status_extended = f"Opensearch domain {domain.name} SEARCH_SLOW_LOGS enabled but INDEX_SLOW_LOGS disabled"

            findings.append(report)

        return findings
