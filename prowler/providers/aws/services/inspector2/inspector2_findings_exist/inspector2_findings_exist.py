from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.inspector2.inspector2_client import (
    inspector2_client,
)


class inspector2_findings_exist(Check):
    def execute(self):
        findings = []
        report = Check_Report_AWS(self.metadata())
        report.status = "FAIL"
        report.status_extended = "There are no Inspector2 findings."
        report.resource_id = "Inspector2"
        report.region = inspector2_client.region
        if len(inspector2_client.inspectors_findings) > 0:
            report.status = "PASS"
            report.status_extended = f"There are {str(len(inspector2_client.inspectors_findings))} Inspector2 findings."

        findings.append(report)

        return findings
