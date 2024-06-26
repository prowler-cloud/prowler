from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.appstream.appstream_client import appstream_client


class appstream_fleet_maximum_session_duration(Check):
    """Check if there are AppStream Fleets with the user maximum session duration no longer than 10 hours"""

    def execute(self):
        """Execute the appstream_fleet_maximum_session_duration check"""

        # max_session_duration_seconds, default: 36000 seconds (10 hours)
        max_session_duration_seconds = appstream_client.audit_config.get(
            "max_session_duration_seconds", 36000
        )

        findings = []
        for fleet in appstream_client.fleets:
            report = Check_Report_AWS(self.metadata())
            report.region = fleet.region
            report.resource_id = fleet.name
            report.resource_arn = fleet.arn
            report.resource_tags = fleet.tags

            if fleet.max_user_duration_in_seconds < max_session_duration_seconds:
                report.status = "PASS"
                report.status_extended = f"Fleet {fleet.name} has the maximum session duration configured for less that 10 hours."
            else:
                report.status = "FAIL"
                report.status_extended = f"Fleet {fleet.name} has the maximum session duration configured for more that 10 hours."

            findings.append(report)

        return findings
