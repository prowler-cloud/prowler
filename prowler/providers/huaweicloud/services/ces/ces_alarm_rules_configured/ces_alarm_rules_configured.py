from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.ces.ces_client import ces_client


class ces_alarm_rules_configured(Check):
    """Check if CES alarm rules are configured and enabled."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []
        
        # NEW: No findings if there are no regional clients
        if not ces_client.regional_clients:
            return findings

        # NEW: Track which regions we've scanned
        scanned_regions = set(ces_client.regional_clients.keys())
        
        # NEW: Group alarms by region to detect regions with no alarms
        alarms_by_region = {}
        for alarm in ces_client.alarms:
            if alarm.region not in alarms_by_region:
                alarms_by_region[alarm.region] = []
            alarms_by_region[alarm.region].append(alarm)

        # NEW: Report per-region findings
        for region in scanned_regions:
            # Check if retrieval failed for this region
            if region in ces_client.regional_failures:
                report = CheckReportHuaweiCloud(
                    metadata=self.metadata(),
                    resource={},
                )
                report.region = region
                report.resource_id = ""
                report.resource_name = "CES Alarms"
                report.resource_arn = f"huaweicloud:ces:{region}:{ces_client.audited_account}:alarms"
                report.status = "UNKNOWN"
                report.status_extended = f"Could not retrieve CES alarm rules: {ces_client.regional_failures[region]}"
                findings.append(report)
                continue

            # Check if region has no alarms
            if region not in alarms_by_region:
                report = CheckReportHuaweiCloud(
                    metadata=self.metadata(),
                    resource={},
                )
                report.region = region
                report.resource_id = ""
                report.resource_name = "CES Alarms"
                report.resource_arn = f"huaweicloud:ces:{region}:{ces_client.audited_account}:alarms"
                report.status = "FAIL"
                report.status_extended = "No CES alarm rules are configured. No alerts will be received for availability or security incidents."
                findings.append(report)

        # Report per-alarm findings
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
