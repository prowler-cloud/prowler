from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.config.config_client import config_client


class config_tracker_enabled(Check):
    """Check if Config (RMS) tracker is enabled for compliance monitoring."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        report = CheckReportHuaweiCloud(
            metadata=self.metadata(), resource=config_client.tracker_config
        )
        report.region = config_client.region
        report.resource_id = f"{config_client.audited_account}-config-tracker"
        report.resource_name = "config-tracker"
        report.resource_arn = (
            f"huaweicloud:config:{config_client.region}:"
            f"{config_client.audited_account}:tracker"
        )

        if config_client.tracker_config.tracker_enabled:
            report.status = "PASS"
            report.status_extended = (
                "Config (RMS) tracker is enabled. "
                "Compliance monitoring is active."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                "Config (RMS) tracker is not enabled. "
                "No compliance monitoring is being performed."
            )

        findings.append(report)

        return findings
