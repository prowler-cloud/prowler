from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.config.config_client import config_client


class config_compliance_rules(Check):
    """Check if Config (RMS) compliance rules are configured."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        if not config_client.policy_assignments:
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource={})
            report.region = config_client.region
            report.resource_id = f"{config_client.audited_account}-config-rules"
            report.resource_name = "config-rules"
            report.resource_arn = (
                f"huaweicloud:config:{config_client.region}:"
                f"{config_client.audited_account}:rules"
            )
            report.status = "FAIL"
            report.status_extended = (
                "No compliance rules are configured in Config (RMS). "
                "Resource configuration compliance is not being monitored."
            )
            findings.append(report)
        else:
            for assignment in config_client.policy_assignments:
                report = CheckReportHuaweiCloud(
                    metadata=self.metadata(), resource=assignment
                )
                report.region = config_client.region
                report.resource_id = assignment.id
                report.resource_arn = (
                    f"huaweicloud:config:{config_client.region}:"
                    f"{config_client.audited_account}:"
                    f"policy-assignment/{assignment.id}"
                )

                if assignment.state == "Enabled":
                    report.status = "PASS"
                    report.status_extended = (
                        f"Compliance rule '{assignment.name}' ({assignment.id}) "
                        f"is enabled and monitoring resource compliance."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Compliance rule '{assignment.name}' ({assignment.id}) "
                        f"is not enabled (state: {assignment.state})."
                    )

                findings.append(report)

        return findings
