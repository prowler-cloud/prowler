from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.directoryservice.directoryservice_client import (
    directoryservice_client,
)


class directoryservice_directory_monitor_notifications(Check):
    def execute(self):
        findings = []
        for directory in directoryservice_client.directories.values():
            report = Check_Report_AWS(self.metadata())
            report.region = directory.region
            report.resource_id = directory.id
            if directory.event_topics:
                report.status = "PASS"
                report.status_extended = (
                    f"Directory Service {directory.id} have SNS messaging enabled"
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Directory Service {directory.id} have SNS messaging disabled"
                )

            findings.append(report)

        return findings
