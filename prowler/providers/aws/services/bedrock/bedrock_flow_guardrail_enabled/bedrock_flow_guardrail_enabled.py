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
    - MANUAL: GetFlow failed or returned no definition, so node configuration
      is unknown rather than empty; or ListFlows failed for a region, so that
      region's flows are unknown rather than absent.

    Retrieve-only KnowledgeBase nodes cannot attach a guardrail and are not
    treated as applicable.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the Bedrock Flow guardrail check.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        for region, error in sorted(bedrock_agent_client.flows_scan_errors.items()):
            report = Check_Report_AWS(
                metadata=self.metadata(), resource={"region": region}
            )
            report.region = region
            report.resource_id = "flow/unknown"
            report.resource_arn = f"arn:{bedrock_agent_client.audited_partition}:bedrock:{region}:{bedrock_agent_client.audited_account}:flow/unknown"
            report.status = "MANUAL"
            report.status_extended = f"Bedrock Flows could not be listed in region {region} ({error}); verify manually that every flow applies a guardrail to applicable prompt nodes."
            findings.append(report)

        for flow in bedrock_agent_client.flows.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=flow)
            if not flow.definition_available:
                report.status = "MANUAL"
                report.status_extended = f"Bedrock Flow {flow.name} definition could not be retrieved in region {flow.region}; verify manually that applicable prompt nodes use a guardrail."
            else:
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
