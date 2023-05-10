from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.resourceexplorer2.resourceexplorer2_client import (
    resource_explorer_2_client,
)


class resourceexplorer2_indexes_found(Check):
    def execute(self):
        findings = []
        report = Check_Report_AWS(self.metadata())
        report.status = "FAIL"
        report.status_extended = "No Resource Explorer Indexes found"
        report.region = resource_explorer_2_client.region
        report.resource_arn = "NoResourceExplorer"
        report.resource_id = resource_explorer_2_client.audited_account
        if resource_explorer_2_client.indexes:
            report.region = resource_explorer_2_client.indexes[0].region
            report.resource_arn = resource_explorer_2_client.indexes[0].arn
            report.status = "PASS"
            report.status_extended = f"Resource Explorer Indexes found: {len(resource_explorer_2_client.indexes)}"
        findings.append(report)

        return findings
