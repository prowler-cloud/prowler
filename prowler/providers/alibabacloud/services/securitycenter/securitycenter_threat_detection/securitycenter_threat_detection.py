from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.lib.check.check_utils import (
    GenericAlibabaCloudResource,
)
from prowler.providers.alibabacloud.services.securitycenter.securitycenter_client import (
    securitycenter_client,
)


class securitycenter_threat_detection(Check):
    def execute(self):
        findings = []
        resource = GenericAlibabaCloudResource(
            id="security-center",
            name="Security Center",
            arn=f"acs:securitycenter::{securitycenter_client.account_id}:config",
            region="global",
        )
        report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=resource)
        report.status = "FAIL"
        report.status_extended = "Security Center threat detection is not enabled."
        if securitycenter_client.config.threat_detection:
            report.status = "PASS"
            report.status_extended = "Security Center threat detection is enabled."
        findings.append(report)
        return findings
