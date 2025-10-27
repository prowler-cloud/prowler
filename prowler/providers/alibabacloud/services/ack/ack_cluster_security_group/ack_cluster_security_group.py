from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ack.ack_client import ack_client


class ack_cluster_security_group(Check):
    def execute(self):
        findings = []
        for cluster in ack_client.clusters.values():
            report = Check_Report_AlibabaCloud(
                metadata=self.metadata(), resource=cluster
            )
            report.status = "FAIL"
            report.status_extended = f"ACK cluster {cluster.cluster_name} does not have a security group configured."
            if cluster.security_group_id:
                report.status = "PASS"
                report.status_extended = f"ACK cluster {cluster.cluster_name} has security group {cluster.security_group_id} configured."
            findings.append(report)
        return findings
