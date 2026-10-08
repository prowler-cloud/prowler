from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.cbr.cbr_client import cbr_client


class cbr_policy_retention(Check):
    """Check if CBR backup policies have sufficient retention (>= 7 days)."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []
        for policy in cbr_client.policies:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(),
                resource=policy,
            )
            report.region = policy.region
            report.resource_id = policy.policy_id
            report.resource_arn = f"huaweicloud:cbr:{policy.region}:{cbr_client.audited_account}:policy/{policy.policy_id}"

            if policy.retention_duration_days >= 7:
                report.status = "PASS"
                report.status_extended = f"CBR policy '{policy.name}' ({policy.policy_id}) has retention of {policy.retention_duration_days} day(s), which meets the minimum of 7 days."
            else:
                report.status = "FAIL"
                report.status_extended = f"CBR policy '{policy.name}' ({policy.policy_id}) has retention of {policy.retention_duration_days} day(s), which is less than the minimum of 7 days."

            findings.append(report)

        return findings
