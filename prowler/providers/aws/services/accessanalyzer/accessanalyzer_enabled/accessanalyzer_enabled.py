from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.accessanalyzer.accessanalyzer_client import (
    accessanalyzer_client,
)


class accessanalyzer_enabled(Check):
    def execute(self):
        findings = []
        for analyzer in accessanalyzer_client.analyzers:
            report = Check_Report_AWS(self.metadata())
            report.region = analyzer.region
            if analyzer.status == "ACTIVE":
                report.status = "PASS"
                report.status_extended = (
                    f"IAM Access Analyzer {analyzer.name} is enabled."
                )
                report.resource_id = analyzer.name
                report.resource_arn = analyzer.arn
                report.resource_tags = analyzer.tags

            elif analyzer.status == "NOT_AVAILABLE":
                report.status = "FAIL"
                report.status_extended = (
                    f"IAM Access Analyzer in account {analyzer.name} is not enabled."
                )
                report.resource_id = analyzer.name
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"IAM Access Analyzer {analyzer.name} is not active."
                )
                report.resource_id = analyzer.name
                report.resource_arn = analyzer.arn
                report.resource_tags = analyzer.tags
            findings.append(report)

        return findings
