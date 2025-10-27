from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ack.ack_client import ack_client


class ack_cluster_public_access(Check):
    def execute(self):
        findings = []
        for cluster in ack_client.clusters.values():
            report = Check_Report_AlibabaCloud(
                metadata=self.metadata(), resource=cluster
            )
            report.status = "FAIL"
            report.status_extended = (
                f"ACK cluster {cluster.cluster_name} API server is publicly accessible."
            )
            if not cluster.public_access:
                report.status = "PASS"
                report.status_extended = f"ACK cluster {cluster.cluster_name} API server is not publicly accessible."
            findings.append(report)
        return findings
