from prowler.lib.check.models import Check, CheckReportE2e
from prowler.providers.e2e.services.node.nodes_client import nodes_client


class node_public_ip_not_assigned(Check):
    def execute(self):
        findings = []
        for node in nodes_client.nodes:
            report = CheckReportE2e(metadata=self.metadata(), resource=node)
            report.status = "PASS"
            report.status_extended = f"Node {node.name} does not have a public IP."
            if node.has_public_ip:
                report.status = "FAIL"
                report.status_extended = f"Node {node.name} has a public IP assigned."
            findings.append(report)
        return findings
