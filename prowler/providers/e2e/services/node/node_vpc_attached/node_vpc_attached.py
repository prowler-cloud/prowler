from prowler.lib.check.models import Check, CheckReportE2e
from prowler.providers.e2e.services.node.nodes_client import nodes_client


class node_vpc_attached(Check):
    def execute(self):
        findings = []
        for node in nodes_client.nodes:
            report = CheckReportE2e(metadata=self.metadata(), resource=node)
            report.status = "PASS"
            report.status_extended = f"Node {node.name} is attached to a VPC."
            if getattr(node, "is_vpc_attached") != True:
                report.status = "FAIL"
                report.status_extended = f"Node {node.name} is not attached to a VPC."
            findings.append(report)
        return findings
