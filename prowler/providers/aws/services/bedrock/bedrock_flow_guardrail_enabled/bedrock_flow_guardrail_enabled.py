from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_agent_client import (
    bedrock_agent_client,
)


class bedrock_flow_guardrail_enabled(Check):
    """Ensure Bedrock Flows apply a guardrail to applicable prompt nodes.

    - PASS: Every applicable Prompt node, and every KnowledgeBase node that
      generates responses, has `guardrailConfiguration.guardrailIdentifier`.
      A flow with no applicable nodes also PASSes, because there is no prompt
      path that can attach a guardrail.
    - FAIL: At least one applicable node has no guardrail identifier.

    A flow whose definition GetFlow could not return produces no finding: its
    node configuration is unknown, and the service already logged the error.

    Retrieve-only KnowledgeBase nodes cannot attach a guardrail and are not
    treated as applicable.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the Bedrock Flow guardrail check.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        for flow in bedrock_agent_client.flows.values():
            if not flow.definition_available:
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=flow)
            applicable = [node for node in flow.nodes if node.applicable]
            missing = [node for node in applicable if not node.guardrail_id]
            if missing:
                node_details = ", ".join(
                    f"{node.name} ({node.type})" for node in missing
                )
                report.status = "FAIL"
                report.status_extended = f"Bedrock Flow {flow.name} has applicable prompt nodes without a guardrail: {node_details} in region {flow.region}."
            elif applicable:
                report.status = "PASS"
                report.status_extended = f"Bedrock Flow {flow.name} applies a guardrail to all applicable prompt nodes in region {flow.region}."
            else:
                report.status = "PASS"
                report.status_extended = f"Bedrock Flow {flow.name} has no applicable prompt or knowledge base nodes that require a guardrail in region {flow.region}."
            findings.append(report)

        return findings
