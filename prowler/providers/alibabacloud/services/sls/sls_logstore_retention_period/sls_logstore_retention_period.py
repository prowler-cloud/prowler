"""
Check: sls_logstore_retention_period

Ensures that the SLS Logstore log retention period is set for 365 days or greater.
Longer retention periods allow for better security analysis and compliance.

Risk Level: MEDIUM
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.sls.sls_client import sls_client


class sls_logstore_retention_period(Check):
    def execute(self):
        findings = []
        for logstore_arn, logstore in sls_client.logstores.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=logstore)
            report.account_uid = sls_client.account_id
            report.region = logstore.region
            report.resource_id = logstore.logstore_name
            report.resource_arn = logstore.arn
            
            if logstore.ttl >= 365:
                report.status = "PASS"
                report.status_extended = f"SLS logstore {logstore.logstore_name} has retention period of {logstore.ttl} days (meets 365+ day requirement)."
            else:
                report.status = "FAIL"
                report.status_extended = f"SLS logstore {logstore.logstore_name} has retention period of only {logstore.ttl} days. Increase to at least 365 days for compliance."
            
            findings.append(report)
        return findings
