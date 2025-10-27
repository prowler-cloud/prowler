from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.sls.sls_client import sls_client


class sls_logstore_encryption_enabled(Check):
    def execute(self):
        findings = []
        for logstore in sls_client.logstores.values():
            report = Check_Report_AlibabaCloud(
                metadata=self.metadata(), resource=logstore
            )
            report.status = "FAIL"
            report.status_extended = f"SLS logstore {logstore.logstore_name} does not have encryption enabled."
            if logstore.encrypt_conf and logstore.encrypt_conf.get("enable", False):
                report.status = "PASS"
                report.status_extended = (
                    f"SLS logstore {logstore.logstore_name} has encryption enabled."
                )
            findings.append(report)
        return findings
