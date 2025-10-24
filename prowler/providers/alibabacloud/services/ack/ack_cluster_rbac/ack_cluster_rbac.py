"""
Check: ack_cluster_rbac

Ensures that ACK clusters have RBAC (Role-Based Access Control) enabled.
RBAC controls access to cluster resources based on user roles and permissions.

Risk Level: HIGH
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ack.ack_client import ack_client


class ack_cluster_rbac(Check):
    """Check if ACK clusters have RBAC enabled"""

    def execute(self):
        """Execute the ack_cluster_rbac check"""
        findings = []

        for cluster_arn, cluster in ack_client.clusters.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=cluster)
            report.account_uid = ack_client.account_id
            report.region = cluster.region
            report.resource_id = cluster.cluster_id
            report.resource_arn = cluster.arn

            if cluster.rbac_enabled:
                report.status = "PASS"
                report.status_extended = f"ACK cluster {cluster.cluster_name} has RBAC enabled for access control."
            else:
                report.status = "FAIL"
                report.status_extended = f"ACK cluster {cluster.cluster_name} does not have RBAC enabled. Enable RBAC to control access to cluster resources based on user roles."

            findings.append(report)

        return findings
