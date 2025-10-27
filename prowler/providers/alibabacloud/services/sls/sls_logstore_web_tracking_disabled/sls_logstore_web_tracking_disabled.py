from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.sls.sls_client import sls_client


class sls_logstore_web_tracking_disabled(Check):
    def execute(self):
        findings = []
        for logstore in sls_client.logstores.values():
            report = Check_Report_AlibabaCloud(
                metadata=self.metadata(), resource=logstore
            )
            report.status = "FAIL"
            report.status_extended = (
                f"SLS logstore {logstore.logstore_name} has web tracking enabled."
            )
            if not logstore.enable_tracking:
                report.status = "PASS"
                report.status_extended = (
                    f"SLS logstore {logstore.logstore_name} has web tracking disabled."
                )
            findings.append(report)
        return findings
