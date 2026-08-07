from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.tms.tms_client import tms_client


class tms_predefined_tags_configured(Check):
    """Ensure TMS predefined tags are configured for governance."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        if tms_client.predefined_tags:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(),
                resource={},
            )
            report.region = tms_client.region
            report.resource_id = tms_client.audited_account
            report.resource_name = "TMS Predefined Tags"
            report.resource_arn = f"huaweicloud:tms:{tms_client.region}:{tms_client.audited_account}:predefined-tags"

            report.status = "PASS"
            report.status_extended = f"{len(tms_client.predefined_tags)} predefined tags are configured for resource governance."

            findings.append(report)
        else:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(),
                resource={},
            )
            report.region = tms_client.region
            report.resource_id = tms_client.audited_account
            report.resource_name = "TMS Predefined Tags"
            report.resource_arn = f"huaweicloud:tms:{tms_client.region}:{tms_client.audited_account}:predefined-tags"

            report.status = "FAIL"
            report.status_extended = "No predefined tags are configured. Without a tagging policy, resources cannot be classified or audited by owner, project, or environment."

            findings.append(report)

        return findings
