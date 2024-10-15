from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudwatch.cloudwatch_client import (
    cloudwatch_client,
)


class cloudwatch_alarm_actions_alarm_state_configured(Check):
    def execute(self):
        findings = []
        for metric_alarm in cloudwatch_client.metric_alarms:
            report = Check_Report_AWS(self.metadata())
            report.region = metric_alarm.region
            report.resource_id = metric_alarm.name
            report.resource_arn = metric_alarm.arn
            report.resource_tags = metric_alarm.tags
            report.status = "PASS"
            report.status_extended = f"CloudWatch metric alarm {metric_alarm.name} has actions configured for the ALARM state."
            if not metric_alarm.alarm_actions:
                report.status = "FAIL"
                report.status_extended = f"CloudWatch metric alarm {metric_alarm.name} does not have actions configured for the ALARM state."
            findings.append(report)
        return findings
