"""
Check: ack_cluster_private_zone

Ensures that ACK clusters have PrivateZone enabled for private DNS resolution.
PrivateZone provides DNS resolution for services within the VPC without exposing to public internet.

Risk Level: LOW
Compliance: Best Practice
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ack.ack_client import ack_client


class ack_cluster_private_zone(Check):
    """Check if ACK clusters have PrivateZone enabled"""

    def execute(self):
        """Execute the ack_cluster_private_zone check"""
        findings = []

        for cluster_arn, cluster in ack_client.clusters.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=cluster)
            report.account_uid = ack_client.account_id
            report.region = cluster.region
            report.resource_id = cluster.cluster_id
            report.resource_arn = cluster.arn

            if cluster.private_zone_enabled:
                report.status = "PASS"
                report.status_extended = f"ACK cluster {cluster.cluster_name} has PrivateZone enabled for private DNS resolution."
            else:
                report.status = "FAIL"
                report.status_extended = f"ACK cluster {cluster.cluster_name} does not have PrivateZone enabled. Consider enabling PrivateZone for enhanced DNS privacy."

            findings.append(report)

        return findings
