"""
Check: sls_logstore_encryption_enabled

Ensures that SLS logstores have encryption enabled to protect log data at rest.
Encryption protects sensitive log data from unauthorized access.

Risk Level: HIGH
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.sls.sls_client import sls_client


class sls_logstore_encryption_enabled(Check):
    """Check if SLS logstores have encryption enabled"""

    def execute(self):
        """Execute the sls_logstore_encryption_enabled check"""
        findings = []

        for logstore_arn, logstore in sls_client.logstores.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=logstore)
            report.account_uid = sls_client.account_id
            report.region = logstore.region
            report.resource_id = logstore.logstore_name
            report.resource_arn = logstore.arn

            if logstore.encrypt_conf and logstore.encrypt_conf.get("enable", False):
                report.status = "PASS"
                encrypt_type = logstore.encrypt_conf.get("encrypt_type", "default")
                report.status_extended = f"SLS logstore {logstore.logstore_name} has encryption enabled using {encrypt_type} encryption."
            else:
                report.status = "FAIL"
                report.status_extended = f"SLS logstore {logstore.logstore_name} does not have encryption enabled. Enable encryption to protect log data at rest."

            findings.append(report)

        return findings
