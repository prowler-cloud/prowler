from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.accessanalyzer.accessanalyzer_client import (
    accessanalyzer_client,
)


class accessanalyzer_enabled(Check):
    def execute(self):
        findings = []
        for analyzer in accessanalyzer_client.analyzers:
            report = Check_Report_AWS(
                metadata=self.metadata(), resource_metadata=analyzer
            )
            if analyzer.status == "ACTIVE":
                report.status = "PASS"
                report.status_extended = (
                    f"IAM Access Analyzer {analyzer.name} is enabled."
                )

            else:
                if analyzer.status == "NOT_AVAILABLE":
                    report.status = "FAIL"
                    report.status_extended = f"IAM Access Analyzer in account {accessanalyzer_client.audited_account} is not enabled."

                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"IAM Access Analyzer {analyzer.name} is not active."
                    )
                if (
                    accessanalyzer_client.audit_config.get(
                        "mute_non_default_regions", False
                    )
                    and not analyzer.region == accessanalyzer_client.region
                ):
                    report.muted = True

            findings.append(report)

        return findings
