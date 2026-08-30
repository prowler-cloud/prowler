from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_agent_client import (
    bedrock_agent_client,
)


class bedrock_agent_idle_session_ttl_not_excessive(Check):
    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        max_ttl = bedrock_agent_client.audit_config.get(
            "max_bedrock_agent_idle_session_ttl_seconds", 3600
        )
        for agent in bedrock_agent_client.agents.values():
            report = Check_Report_AWS(
                metadata=self.metadata(),
                resource=agent,
            )
            ttl = getattr(agent, "idle_session_ttl_seconds", None)
            detail_ok = getattr(agent, "detail_retrieved", False)

            if not detail_ok or ttl is None:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Bedrock Agent {agent.name} idle session TTL could not be determined."
                )
            elif ttl > max_ttl:
                report.status = "FAIL"
                report.status_extended = (
                    f"Bedrock Agent {agent.name} idle session TTL is {ttl} seconds, "
                    f"which exceeds the configured maximum of {max_ttl} seconds."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Bedrock Agent {agent.name} idle session TTL is {ttl} seconds, "
                    f"which does not exceed the configured maximum of {max_ttl} seconds."
                )
            findings.append(report)
        return findings
