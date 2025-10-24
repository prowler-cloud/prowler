"""
Check: ack_cluster_encryption

Ensures that ACK clusters have encryption enabled for data at rest.
Encryption protects sensitive Kubernetes secrets and configuration data.

Risk Level: HIGH
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ack.ack_client import ack_client


class ack_cluster_encryption(Check):
    """Check if ACK clusters have encryption enabled"""

    def execute(self):
        """Execute the ack_cluster_encryption check"""
        findings = []

        for cluster_arn, cluster in ack_client.clusters.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=cluster)
            report.account_uid = ack_client.account_id
            report.region = cluster.region
            report.resource_id = cluster.cluster_id
            report.resource_arn = cluster.arn

            if cluster.encryption_enabled:
                report.status = "PASS"
                report.status_extended = f"ACK cluster {cluster.cluster_name} has encryption enabled for data at rest."
            else:
                report.status = "FAIL"
                report.status_extended = f"ACK cluster {cluster.cluster_name} does not have encryption enabled. Enable encryption to protect Kubernetes secrets and configuration data."

            findings.append(report)

        return findings
