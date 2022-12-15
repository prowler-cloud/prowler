from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.accessanalyzer.accessanalyzer_client import (
    accessanalyzer_client,
)


class accessanalyzer_enabled_without_findings(Check):
    def execute(self):
        findings = []
        for analyzer in accessanalyzer_client.analyzers:
            report = Check_Report_AWS(self.metadata())
            report.region = analyzer.region
            if analyzer.status == "ACTIVE":
                if analyzer.findings_count > 0:
                    report.status = "FAIL"
                    report.status_extended = f"IAM Access Analyzer {analyzer.name} has {analyzer.findings_count} active findings"
                    report.resource_id = analyzer.name
                    report.resource_arn = analyzer.arn
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"IAM Access Analyzer {analyzer.name} has no active findings"
                    )
                    report.resource_id = analyzer.name
                    report.resource_arn = analyzer.arn
            elif analyzer.status == "NOT_AVAILABLE":
                report.status = "FAIL"
                report.status_extended = "IAM Access Analyzer is not enabled"
                report.resource_id = analyzer.name
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"IAM Access Analyzer {analyzer.name} is not active"
                )
                report.resource_id = analyzer.name
                report.resource_arn = analyzer.arn
            findings.append(report)

        return findings
