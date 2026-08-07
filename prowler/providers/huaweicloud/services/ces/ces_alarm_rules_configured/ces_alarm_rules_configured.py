from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.ces.ces_client import ces_client


class ces_alarm_rules_configured(Check):
    """Check if CES alarm rules are configured and enabled."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []
        if not ces_client.alarms:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(),
                resource={},
            )
            report.region = ces_client.region
            report.resource_id = ""
            report.resource_name = "CES Alarms"
            report.resource_arn = f"huaweicloud:ces:{ces_client.region}:{ces_client.audited_account}:alarms"
            report.status = "FAIL"
            report.status_extended = "No CES alarm rules are configured. No alerts will be received for availability or security incidents."
            findings.append(report)
            return findings

        for alarm in ces_client.alarms:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(),
                resource=alarm,
            )
            report.region = alarm.region
            report.resource_id = alarm.alarm_id
            report.resource_name = alarm.alarm_name
            report.resource_arn = f"huaweicloud:ces:{alarm.region}:{ces_client.audited_account}:alarm/{alarm.alarm_id}"

            if alarm.alarm_enabled:
                report.status = "PASS"
                report.status_extended = f"CES alarm rule '{alarm.alarm_name}' ({alarm.alarm_id}) is enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"CES alarm rule '{alarm.alarm_name}' ({alarm.alarm_id}) is disabled."

            findings.append(report)

        return findings
