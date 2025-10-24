"""
Check: actiontrail_trail_logs_all_events

Ensures that ActionTrail trails are configured to log both read and write events.
Logging all events provides complete audit coverage for security analysis and compliance.

Risk Level: MEDIUM
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.actiontrail.actiontrail_client import actiontrail_client


class actiontrail_trail_logs_all_events(Check):
    """Check if ActionTrail trails log all events (read and write)"""

    def execute(self):
        """Execute the actiontrail_trail_logs_all_events check"""
        findings = []

        for trail_arn, trail in actiontrail_client.trails.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=trail)
            report.account_uid = actiontrail_client.account_id
            report.region = trail.region
            report.resource_id = trail.name
            report.resource_arn = trail.arn

            if trail.event_rw == "All":
                report.status = "PASS"
                report.status_extended = f"ActionTrail trail {trail.name} logs all events (read and write)."
            else:
                report.status = "FAIL"
                report.status_extended = f"ActionTrail trail {trail.name} only logs {trail.event_rw} events. Configure the trail to log all events (read and write) for complete audit coverage."

            findings.append(report)

        return findings
