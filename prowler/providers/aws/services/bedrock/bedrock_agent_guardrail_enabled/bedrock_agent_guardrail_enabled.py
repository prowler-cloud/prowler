from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_agent_client import (
    bedrock_agent_client,
)


class bedrock_agent_guardrail_enabled(Check):
    def execute(self):
        findings = []
        for agent in bedrock_agent_client.agents.values():
            report = Check_Report_AWS(self.metadata())
            report.region = agent.region
            report.resource_id = agent.id
            report.resource_arn = agent.arn
            report.resource_tags = agent.tags
            report.status = "FAIL"
            report.status_extended = f"Bedrock Agent {agent.name} is not using any guardrail to protect agent sessions."
            if agent.guardrail_id:
                report.status = "PASS"
                report.status_extended = f"Bedrock Agent {agent.name} is using guardrail {agent.guardrail_id} to protect agent sessions."

            findings.append(report)

        return findings
