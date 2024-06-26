from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.inspector2.inspector2_client import (
    inspector2_client,
)


class inspector2_active_findings_exist(Check):
    def execute(self):
        findings = []
        for inspector in inspector2_client.inspectors:
            if inspector.status == "ENABLED":
                report = Check_Report_AWS(self.metadata())
                report.resource_id = inspector.id
                report.resource_arn = inspector.arn
                report.region = inspector.region
                active_findings = 0
                report.status = "PASS"
                report.status_extended = "Inspector2 is enabled with no findings."
                for finding in inspector.findings:
                    if finding.status == "ACTIVE":
                        active_findings += 1
                if len(inspector.findings) > 0:
                    report.status_extended = (
                        "Inspector2 is enabled with no active findings."
                    )
                    if active_findings > 0:
                        report.status = "FAIL"
                        report.status_extended = (
                            f"There are {active_findings} active Inspector2 findings."
                        )
                findings.append(report)

        return findings
