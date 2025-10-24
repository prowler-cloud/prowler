"""
Check: ack_cluster_vpc

Ensures that ACK clusters are deployed within a VPC (Virtual Private Cloud).
Running clusters in a VPC provides network isolation and enhanced security controls.

Risk Level: HIGH
Compliance: Best Practice
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ack.ack_client import ack_client


class ack_cluster_vpc(Check):
    """Check if ACK clusters are deployed in a VPC"""

    def execute(self):
        """Execute the ack_cluster_vpc check"""
        findings = []

        for cluster_arn, cluster in ack_client.clusters.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=cluster)
            report.account_uid = ack_client.account_id
            report.region = cluster.region
            report.resource_id = cluster.cluster_id
            report.resource_arn = cluster.arn

            if cluster.vpc_id:
                report.status = "PASS"
                report.status_extended = f"ACK cluster {cluster.cluster_name} is deployed in VPC {cluster.vpc_id}."
            else:
                report.status = "FAIL"
                report.status_extended = f"ACK cluster {cluster.cluster_name} is not deployed in a VPC. Deploy clusters in VPC for network isolation and enhanced security."

            findings.append(report)

        return findings
