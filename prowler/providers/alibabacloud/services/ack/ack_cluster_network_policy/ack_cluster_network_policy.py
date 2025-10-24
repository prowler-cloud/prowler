"""
Check: ack_cluster_network_policy

Ensures that ACK clusters have network policy support enabled.
Network policies control traffic between pods and enhance security isolation.

Risk Level: MEDIUM
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ack.ack_client import ack_client


class ack_cluster_network_policy(Check):
    """Check if ACK clusters have network policy support enabled"""

    def execute(self):
        """Execute the ack_cluster_network_policy check"""
        findings = []

        for cluster_arn, cluster in ack_client.clusters.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=cluster)
            report.account_uid = ack_client.account_id
            report.region = cluster.region
            report.resource_id = cluster.cluster_id
            report.resource_arn = cluster.arn

            if cluster.network_policy_enabled:
                report.status = "PASS"
                report.status_extended = f"ACK cluster {cluster.cluster_name} has network policy support enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"ACK cluster {cluster.cluster_name} does not have network policy support enabled. Enable network policies to control traffic between pods."

            findings.append(report)

        return findings
