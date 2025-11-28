from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.securitycenter.securitycenter_client import (
    securitycenter_client,
)


class securitycenter_notification_enabled_high_risk(Check):
    """Check if notification is enabled on all high risk items."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        # High-risk categories based on CIS benchmark:
        # - Vulnerability: sas_vulnerability, yundun_sas_vul_Emergency
        # - Baseline Risks: sas_healthcheck
        # - Alerts: sas_suspicious, suspicious, remotelogin, webshell, bruteforcesuccess
        # - Accesskey Leak: yundun_sas_ak_leakage
        high_risk_projects = [
            "sas_vulnerability",  # Vulnerability
            "yundun_sas_vul_Emergency",  # Emergency vulnerabilities
            "sas_healthcheck",  # Baseline Risks
            "sas_suspicious",  # Alerts - Suspicious
            "suspicious",  # Alerts - Suspicious
            "remotelogin",  # Alerts - Remote login
            "webshell",  # Alerts - Webshell
            "bruteforcesuccess",  # Alerts - Brute force success
            "yundun_sas_ak_leakage",  # Accesskey Leak
        ]

        notice_configs = securitycenter_client.notice_configs

        # Check each high-risk project
        for project in high_risk_projects:
            config = notice_configs.get(project)

            report = CheckReportAlibabaCloud(
                metadata=self.metadata(), resource=config if config else {}
            )
            report.region = securitycenter_client.region
            report.resource_id = project
            report.resource_arn = f"acs:sas::{securitycenter_client.audited_account}:notice-config/{project}"

            if not config:
                # Configuration not found - may not be available or not configured
                report.status = "MANUAL"
                report.status_extended = (
                    f"Notification configuration for high-risk item '{project}' "
                    "could not be determined. Please check Security Center Console manually."
                )
            elif config.notification_enabled:
                # Route != 0 means notification is enabled
                report.status = "PASS"
                report.status_extended = (
                    f"Notification is enabled for high-risk item '{project}'."
                )
            else:
                # Route == 0 means notification is disabled
                report.status = "FAIL"
                report.status_extended = (
                    f"Notification is not enabled for high-risk item '{project}'."
                )

            findings.append(report)

        return findings
