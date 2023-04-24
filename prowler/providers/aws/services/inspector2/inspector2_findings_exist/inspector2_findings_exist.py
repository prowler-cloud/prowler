from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.inspector2.inspector2_client import (
    inspector2_client,
)


class inspector2_findings_exist(Check):
    def execute(self):
        findings = []
        for inspector in inspector2_client.inspectors:
            report = Check_Report_AWS(self.metadata())
            report.status = "FAIL"
            report.status_extended = "Inspector2 is not enabled."
            report.resource_id = inspector.id
            report.resource_arn = ""
            report.region = inspector.region
            if inspector.status == "ENABLED":
                report.status = "PASS"
                report.status_extended = "Inspector2 is enabled with no findings"
                for finding in inspector.findings:
                    report.status_extended = (
                        "Inspector2 is enabled with no active findings"
                    )
                    if finding.status == "ACTIVE":
                        report.status = "FAIL"
                        report.status_extended = f"There are {str(len(inspector.findings))} ACTIVE Inspector2 findings."
                        break

            findings.append(report)

        return findings
