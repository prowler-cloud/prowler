from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.lts.lts_client import lts_client


class lts_log_group_retention(Check):
    """Check if LTS log groups have adequate retention period (>= 30 days)."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []
        if not lts_client.log_groups:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(),
                resource={},
            )
            report.region = lts_client.region
            report.resource_id = ""
            report.resource_name = "LTS Log Groups"
            report.resource_arn = f"huaweicloud:lts:{lts_client.region}:{lts_client.audited_account}:log-groups"
            report.status = "FAIL"
            report.status_extended = "No LTS log groups are configured. Log data is not being collected for analysis and incident investigation."
            findings.append(report)
            return findings

        for group in lts_client.log_groups:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(),
                resource=group,
            )
            report.region = group.region
            report.resource_id = group.log_group_id
            report.resource_name = group.log_group_name
            report.resource_arn = f"huaweicloud:lts:{group.region}:{lts_client.audited_account}:log-group/{group.log_group_id}"

            if group.ttl_in_days is not None and group.ttl_in_days >= 30:
                report.status = "PASS"
                report.status_extended = f"LTS log group '{group.log_group_name}' ({group.log_group_id}) has retention of {group.ttl_in_days} days."
            else:
                ttl = group.ttl_in_days if group.ttl_in_days is not None else 0
                report.status = "FAIL"
                report.status_extended = f"LTS log group '{group.log_group_name}' ({group.log_group_id}) has retention of {ttl} days. Minimum 30 days recommended for incident investigation."

            findings.append(report)

        return findings
