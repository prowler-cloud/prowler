"""
Check: ack_cluster_security_group

Ensures that ACK clusters have security groups configured.
Security groups act as virtual firewalls to control inbound and outbound traffic.

Risk Level: HIGH
Compliance: Best Practice
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ack.ack_client import ack_client


class ack_cluster_security_group(Check):
    """Check if ACK clusters have security groups configured"""

    def execute(self):
        """Execute the ack_cluster_security_group check"""
        findings = []

        for cluster_arn, cluster in ack_client.clusters.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=cluster)
            report.account_uid = ack_client.account_id
            report.region = cluster.region
            report.resource_id = cluster.cluster_id
            report.resource_arn = cluster.arn

            if cluster.security_group_id:
                report.status = "PASS"
                report.status_extended = f"ACK cluster {cluster.cluster_name} has security group {cluster.security_group_id} configured."
            else:
                report.status = "FAIL"
                report.status_extended = f"ACK cluster {cluster.cluster_name} does not have a security group configured. Configure a security group to control network traffic."

            findings.append(report)

        return findings
