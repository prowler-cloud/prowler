from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.resourceexplorer2.resourceexplorer2_client import (
    resource_explorer_2_client,
)


class resourceexplorer2_indexes_found(Check):
    def execute(self):
        findings = []
        if resource_explorer_2_client.indexes:
            report = Check_Report_AWS(self.metadata())
            report.region = resource_explorer_2_client.indexes[0].region
            report.resource_id = resource_explorer_2_client.audited_account
            report.resource_arn = resource_explorer_2_client.indexes[0].arn
            report.status = "PASS"
            report.status_extended = f"Resource Explorer Indexes found: {len(resource_explorer_2_client.indexes)}."
            findings.append(report)
        elif not resource_explorer_2_client.audit_info.ignore_unused_services:
            report = Check_Report_AWS(self.metadata())
            report.status = "FAIL"
            report.status_extended = "AWS Resource Explorer is not enabled."
            report.region = resource_explorer_2_client.region
            report.resource_id = resource_explorer_2_client.audited_account
            report.resource_arn = resource_explorer_2_client.audited_account_arn
            findings.append(report)

        return findings
