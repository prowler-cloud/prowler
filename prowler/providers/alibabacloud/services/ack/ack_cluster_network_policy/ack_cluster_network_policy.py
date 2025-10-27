from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ack.ack_client import ack_client


class ack_cluster_network_policy(Check):
    def execute(self):
        findings = []
        for cluster in ack_client.clusters.values():
            report = Check_Report_AlibabaCloud(
                metadata=self.metadata(), resource=cluster
            )
            report.status = "FAIL"
            report.status_extended = f"ACK cluster {cluster.cluster_name} does not have network policy support enabled."
            if cluster.network_policy_enabled:
                report.status = "PASS"
                report.status_extended = f"ACK cluster {cluster.cluster_name} has network policy support enabled."
            findings.append(report)
        return findings
