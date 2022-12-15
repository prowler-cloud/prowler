from prowler.config.config import get_config_var
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.appstream.appstream_client import appstream_client

max_disconnect_timeout_in_seconds = get_config_var("max_disconnect_timeout_in_seconds")
"""max_disconnect_timeout_in_seconds, default: 300 seconds (5 minutes)"""


class appstream_fleet_session_disconnect_timeout(Check):
    """Check if there are AppStream Fleets with the session disconnect timeout set to 5 minutes or less"""

    def execute(self):
        """Execute the appstream_fleet_maximum_session_duration check"""
        findings = []
        for fleet in appstream_client.fleets:
            report = Check_Report_AWS(self.metadata())
            report.region = fleet.region
            report.resource_id = fleet.name
            report.resource_arn = fleet.arn

            if fleet.disconnect_timeout_in_seconds <= max_disconnect_timeout_in_seconds:
                report.status = "PASS"
                report.status_extended = f"Fleet {fleet.name} has the session disconnect timeout set to less than 5 minutes"

            else:
                report.status = "FAIL"
                report.status_extended = f"Fleet {fleet.name} has the session disconnect timeout set to more than 5 minutes"

            findings.append(report)

        return findings
