from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.actiontrail.actiontrail_client import (
    actiontrail_client,
)


class actiontrail_trail_logs_all_events(Check):
    def execute(self):
        findings = []
        for trail in actiontrail_client.trails.values():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=trail)
            report.status = "FAIL"
            report.status_extended = (
                f"ActionTrail trail {trail.name} only logs {trail.event_rw} events."
            )
            if trail.event_rw == "All":
                report.status = "PASS"
                report.status_extended = (
                    f"ActionTrail trail {trail.name} logs all events."
                )
            findings.append(report)
        return findings
