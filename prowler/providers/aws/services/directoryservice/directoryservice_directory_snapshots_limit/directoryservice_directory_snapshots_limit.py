from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.directoryservice.directoryservice_client import (
    directoryservice_client,
)

SNAPSHOT_LIMIT_THRESHOLD = 2
"""Number of remaining snapshots to reach the limit"""


class directoryservice_directory_snapshots_limit(Check):
    def execute(self):
        findings = []
        for directory in directoryservice_client.directories.values():
            report = Check_Report_AWS(self.metadata())
            report.region = directory.region
            report.resource_id = directory.id
            if directory.snapshots_limits:
                if directory.snapshots_limits.manual_snapshots_limit_reached:
                    report.status = "FAIL"
                    report.status_extended = f"Directory Service {directory.id} reached {directory.snapshots_limits.manual_snapshots_limit} Snapshots limit"
                else:
                    limit_remaining = (
                        directory.snapshots_limits.manual_snapshots_limit
                        - directory.snapshots_limits.manual_snapshots_current_count
                    )
                    if limit_remaining <= SNAPSHOT_LIMIT_THRESHOLD:
                        report.status = "FAIL"
                        report.status_extended = f"Directory Service {directory.id} is about to reach {directory.snapshots_limits.manual_snapshots_limit} Snapshots which is the limit"
                    else:
                        report.status = "PASS"
                        report.status_extended = f"Directory Service {directory.id} is using {directory.snapshots_limits.manual_snapshots_current_count} out of {directory.snapshots_limits.manual_snapshots_limit} from the Snapshots Limit"
                findings.append(report)

        return findings
