from prowler.lib.check.models import Check, CheckReportE2e
from prowler.providers.e2e.services.node.nodes_client import nodes_client


class node_compliance_enabled(Check):
    def execute(self):
        findings = []
        for node in nodes_client.nodes:
            report = CheckReportE2e(metadata=self.metadata(), resource=node)
            report.status = "PASS"
            report.status_extended = f"Node {node.name} has compliance mode enabled."
            if not node.is_node_compliance:
                report.status = "FAIL"
                report.status_extended = f"Node {node.name} does not have compliance mode enabled."
            findings.append(report)
        return findings
