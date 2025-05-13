from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudwatch.cloudwatch_client import (
    cloudwatch_client,
)


class cloudwatch_alarm_actions_enabled(Check):
    def execute(self):
        findings = []
        if cloudwatch_client.metric_alarms is not None:
            for metric_alarm in cloudwatch_client.metric_alarms:
                report = Check_Report_AWS(
                    metadata=self.metadata(), resource=metric_alarm
                )
                report.status = "PASS"
                report.status_extended = (
                    f"CloudWatch metric alarm {metric_alarm.name} has actions enabled."
                )
                if not metric_alarm.actions_enabled:
                    report.status = "FAIL"
                    report.status_extended = f"CloudWatch metric alarm {metric_alarm.name} does not have actions enabled."
                findings.append(report)
        return findings
