from prowler.lib.check.models import Check, CheckReportE2e
from prowler.providers.e2e.services.node.nodes_client import nodes_client


class node_accidental_protection_enabled(Check):
    def execute(self):
        findings = []
        for node in nodes_client.nodes:
            report = CheckReportE2e(metadata=self.metadata(), resource=node)
            report.status = "PASS"
            report.status_extended = f"Node {node.name} has accidental protection enabled."
            if getattr(node, "is_accidental_protection") != True:
                report.status = "FAIL"
                report.status_extended = f"Node {node.name} does not have accidental protection enabled."
            findings.append(report)
        return findings
