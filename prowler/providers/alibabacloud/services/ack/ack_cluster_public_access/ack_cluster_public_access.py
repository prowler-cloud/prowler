"""
Check: ack_cluster_public_access

Ensures that ACK cluster API servers are not publicly accessible from the internet.
Public access to Kubernetes API servers increases the attack surface.

Risk Level: HIGH
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ack.ack_client import ack_client


class ack_cluster_public_access(Check):
    """Check if ACK clusters have public access disabled"""

    def execute(self):
        """Execute the ack_cluster_public_access check"""
        findings = []

        for cluster_arn, cluster in ack_client.clusters.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=cluster)
            report.account_uid = ack_client.account_id
            report.region = cluster.region
            report.resource_id = cluster.cluster_id
            report.resource_arn = cluster.arn

            if not cluster.public_access:
                report.status = "PASS"
                report.status_extended = f"ACK cluster {cluster.cluster_name} API server is not publicly accessible."
            else:
                report.status = "FAIL"
                report.status_extended = f"ACK cluster {cluster.cluster_name} API server is publicly accessible. Restrict access to private networks only."

            findings.append(report)

        return findings
