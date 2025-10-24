from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.securitycenter.securitycenter_client import securitycenter_client

class securitycenter_enabled(Check):
    def execute(self):
        findings = []
        report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=type('obj', (object,), {
            'id': 'security-center', 'name': 'Security Center', 
            'arn': f"acs:securitycenter::{securitycenter_client.account_id}:config", 'region': 'global'
        })())
        report.account_uid = securitycenter_client.account_id
        report.region = "global"
        report.resource_id = "security-center"
        report.resource_arn = f"acs:securitycenter::{securitycenter_client.account_id}:config"
        
        if securitycenter_client.config.enabled:
            report.status = "PASS"
            report.status_extended = "Security Center is enabled."
        else:
            report.status = "FAIL"
            report.status_extended = "Security Center is not enabled. Enable Security Center for threat detection and security monitoring."
        findings.append(report)
        return findings
