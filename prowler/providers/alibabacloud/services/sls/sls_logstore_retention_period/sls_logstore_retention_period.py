from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.sls.sls_client import sls_client


class sls_logstore_retention_period(Check):
    def execute(self):
        findings = []
        for logstore in sls_client.logstores.values():
            report = Check_Report_AlibabaCloud(
                metadata=self.metadata(), resource=logstore
            )
            report.status = "FAIL"
            report.status_extended = f"SLS logstore {logstore.logstore_name} has retention period of only {logstore.ttl} days."
            if logstore.ttl >= 365:
                report.status = "PASS"
                report.status_extended = f"SLS logstore {logstore.logstore_name} has retention period of {logstore.ttl} days."
            findings.append(report)
        return findings
