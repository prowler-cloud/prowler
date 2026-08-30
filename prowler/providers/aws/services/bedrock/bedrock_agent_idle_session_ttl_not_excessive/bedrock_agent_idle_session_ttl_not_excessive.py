from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_agent_client import (
    bedrock_agent_client,
)


class bedrock_agent_idle_session_ttl_not_excessive(Check):
    """Check that Bedrock Agent idle session TTL is not excessive.

    This check verifies that Amazon Bedrock Agents are configured with
    an idle session TTL at or below the configured maximum (default 3600s).
    A shorter TTL reduces the window for session reuse and stale context.

    Attributes:
        metadata: Inherited check metadata.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check for Bedrock Agent idle session TTL.

        Evaluates each collected Bedrock Agent against the maximum TTL.
        Returns MANUAL when detail retrieval failed or TTL is missing,
        FAIL when TTL exceeds the threshold, and PASS otherwise.

        Returns:
            list[Check_Report_AWS]: List of findings with PASS, FAIL, or MANUAL.
        """
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
