from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.accessanalyzer.accessanalyzer_client import (
    accessanalyzer_client,
)


class accessanalyzer_enabled_without_findings(Check):
    def execute(self):
        findings = []
        for analyzer in accessanalyzer_client.analyzers:
            report = Check_Report_AWS(metadata=self.metadata(), resource=analyzer)
            if analyzer.status == "ACTIVE":
                report.status = "PASS"
                report.status_extended = f"IAM Access Analyzer {analyzer.name} does not have active findings."

                if len(analyzer.findings) != 0:
                    active_finding_counter = 0
                    for finding in analyzer.findings:
                        if finding.status == "ACTIVE":
                            active_finding_counter += 1

                    if active_finding_counter > 0:
                        report.status = "FAIL"
                        report.status_extended = f"IAM Access Analyzer {analyzer.name} has {active_finding_counter} active findings."

                findings.append(report)

        return findings
