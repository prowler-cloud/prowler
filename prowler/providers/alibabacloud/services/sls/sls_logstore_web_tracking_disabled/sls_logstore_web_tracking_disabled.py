"""
Check: sls_logstore_web_tracking_disabled

Ensures that SLS logstores have web tracking disabled for security.
Web tracking allows public access to write logs without authentication, which can be a security risk.

Risk Level: MEDIUM
Compliance: Best Practice
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.sls.sls_client import sls_client


class sls_logstore_web_tracking_disabled(Check):
    """Check if SLS logstores have web tracking disabled"""

    def execute(self):
        """Execute the sls_logstore_web_tracking_disabled check"""
        findings = []

        for logstore_arn, logstore in sls_client.logstores.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=logstore)
            report.account_uid = sls_client.account_id
            report.region = logstore.region
            report.resource_id = logstore.logstore_name
            report.resource_arn = logstore.arn

            if not logstore.enable_tracking:
                report.status = "PASS"
                report.status_extended = f"SLS logstore {logstore.logstore_name} has web tracking disabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"SLS logstore {logstore.logstore_name} has web tracking enabled. Disable web tracking to prevent unauthenticated log write access."

            findings.append(report)

        return findings
