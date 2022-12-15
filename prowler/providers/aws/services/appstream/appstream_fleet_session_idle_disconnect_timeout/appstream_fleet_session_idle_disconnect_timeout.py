from prowler.config.config import get_config_var
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.appstream.appstream_client import appstream_client

max_idle_disconnect_timeout_in_seconds = get_config_var(
    "max_idle_disconnect_timeout_in_seconds"
)
"""max_idle_disconnect_timeout_in_seconds, default: 600 seconds (10 minutes)"""


class appstream_fleet_session_idle_disconnect_timeout(Check):
    """Check if there are AppStream Fleets with the idle disconnect timeout set to 10 minutes or less"""

    def execute(self):
        """Execute the appstream_fleet_session_idle_disconnect_timeout check"""
        findings = []
        for fleet in appstream_client.fleets:
            report = Check_Report_AWS(self.metadata())
            report.region = fleet.region
            report.resource_id = fleet.name
            report.resource_arn = fleet.arn

            if (
                fleet.idle_disconnect_timeout_in_seconds
                <= max_idle_disconnect_timeout_in_seconds
            ):
                report.status = "PASS"
                report.status_extended = f"Fleet {fleet.name} has the session idle disconnect timeout set to less than 10 minutes"

            else:
                report.status = "FAIL"
                report.status_extended = f"Fleet {fleet.name} has the session idle disconnect timeout set to more than 10 minutes"

            findings.append(report)

        return findings
