"""
Check: ack_cluster_audit_log

Ensures that ACK clusters have audit logging enabled with Simple Log Service (SLS).
Audit logs are essential for security monitoring, troubleshooting, and compliance.

Risk Level: HIGH
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ack.ack_client import ack_client


class ack_cluster_audit_log(Check):
    """Check if ACK clusters have audit logging enabled"""

    def execute(self):
        """Execute the ack_cluster_audit_log check"""
        findings = []

        for cluster_arn, cluster in ack_client.clusters.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=cluster)
            report.account_uid = ack_client.account_id
            report.region = cluster.region
            report.resource_id = cluster.cluster_id
            report.resource_arn = cluster.arn

            if cluster.audit_log_enabled:
                report.status = "PASS"
                report.status_extended = f"ACK cluster {cluster.cluster_name} has audit logging enabled with SLS."
            else:
                report.status = "FAIL"
                report.status_extended = f"ACK cluster {cluster.cluster_name} does not have audit logging enabled. Enable audit logging with Simple Log Service for security monitoring and compliance."

            findings.append(report)

        return findings
