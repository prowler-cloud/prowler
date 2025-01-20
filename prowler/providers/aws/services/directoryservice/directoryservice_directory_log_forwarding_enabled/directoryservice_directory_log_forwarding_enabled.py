from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.directoryservice.directoryservice_client import (
    directoryservice_client,
)


class directoryservice_directory_log_forwarding_enabled(Check):
    def execute(self):
        findings = []
        for directory in directoryservice_client.directories.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=directory)
            if directory.log_subscriptions:
                report.status = "PASS"
                report.status_extended = f"Directory Service {directory.id} have log forwarding to CloudWatch enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"Directory Service {directory.id} have log forwarding to CloudWatch disabled."

            findings.append(report)

        return findings
