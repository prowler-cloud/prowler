from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.securitycenter.securitycenter_client import (
    securitycenter_client,
)


class securitycenter_advanced_or_enterprise_edition(Check):
    """Check if Security Center is Advanced or Enterprise Edition."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        report = CheckReportAlibabaCloud(metadata=self.metadata(), resource={})
        report.region = securitycenter_client.region
        report.resource_id = securitycenter_client.audited_account
        report.resource_arn = (
            f"acs:sas::{securitycenter_client.audited_account}:security-center"
        )

        version = securitycenter_client.version
        edition = securitycenter_client.edition

        if version is None or edition == "Unknown":
            report.status = "MANUAL"
            report.status_extended = (
                "Security Center edition could not be determined. "
                "Please check Security Center Console manually."
            )
        else:
            # Check if version is 3 (Enterprise) or 5 (Advanced)
            # Version mapping: 1=Basic, 3=Enterprise, 5=Advanced, 6=Anti-virus, 7=Ultimate, 8=Multi-Version, 10=Value-added Plan
            if version == 3 or version == 5:
                report.status = "PASS"
                report.status_extended = (
                    f"Security Center is {edition} edition (Version {version}), which provides "
                    "threat detection for network and endpoints, malware detection, "
                    "webshell detection and anomaly detection."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Security Center is {edition} edition (Version {version}). "
                    "It is recommended to use Advanced Edition (Version 5) or Enterprise Edition (Version 3) "
                    "for full protection to defend cloud threats."
                )

        findings.append(report)
        return findings
