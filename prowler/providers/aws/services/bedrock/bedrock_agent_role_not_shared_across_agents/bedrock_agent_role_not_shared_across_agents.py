from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_agent_client import (
    bedrock_agent_client,
)

# A role used by exactly one agent is dedicated. Two or more sharing it is the
# failing condition, so the count is compared against this threshold.
SHARED_ROLE_AGENT_COUNT = 2


class bedrock_agent_role_not_shared_across_agents(Check):
    """Ensure each Bedrock Agent has a dedicated execution role.

    A shared `agentResourceRoleArn` means every agent using it inherits the
    union of all their permissions, so the least-privileged agent in the set
    still holds the rights of the most privileged one. It also destroys
    attribution: CloudTrail records the role session, so an action taken with
    that role cannot be tied back to a single agent.

    - PASS: The agent's execution role is used by no other agent in the
      account inventory.
    - FAIL: Two or more agents share the role; the other agents sharing it are
      named in the message.
    - MANUAL: The execution role ARN could not be retrieved from GetAgent, so
      sharing can be neither confirmed nor ruled out.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        # Build the account-wide role -> agents index once, from every agent
        # whose role could actually be read. Keyed on the agent ARN rather than
        # the name so two agents that happen to share a name still count twice.
        agents_by_role = {}
        for agent in bedrock_agent_client.agents.values():
            if agent.detail_retrieved and agent.role_arn:
                agents_by_role.setdefault(agent.role_arn, []).append(
                    (agent.arn, agent.name or agent.id)
                )

        for agent in bedrock_agent_client.agents.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=agent)
            name = agent.name or agent.id

            if not agent.detail_retrieved or not agent.role_arn:
                # GetAgent failed or returned no role. Do not assert
                # compliance from an absent answer.
                report.status = "MANUAL"
                report.status_extended = f"Bedrock Agent {name} execution role could not be retrieved in region {agent.region}; verify manually that no other agent shares it."
                findings.append(report)
                continue

            sharing_agents = agents_by_role[agent.role_arn]
            if len(sharing_agents) >= SHARED_ROLE_AGENT_COUNT:
                # Sorted for deterministic output across scans.
                others = sorted(
                    other_name
                    for other_arn, other_name in sharing_agents
                    if other_arn != agent.arn
                )
                report.status = "FAIL"
                report.status_extended = f"Bedrock Agent {name} shares execution role {agent.role_arn} with {', '.join(others)} in region {agent.region}, so each agent inherits the union of their permissions and CloudTrail cannot attribute an action to one of them."
            else:
                report.status = "PASS"
                report.status_extended = f"Bedrock Agent {name} has a dedicated execution role in region {agent.region}."
            findings.append(report)

        return findings
