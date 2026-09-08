from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_agent_client import (
    bedrock_agent_client,
)

SHARED_ROLE_AGENT_COUNT = 2


class bedrock_agent_role_not_shared_across_agents(Check):
    """Ensure each Bedrock Agent has a dedicated execution role.

    A shared `agentResourceRoleArn` means every agent using it inherits the
    union of all their permissions, so the least-privileged agent in the set
    still holds the rights of the most privileged one. It also destroys
    attribution: CloudTrail records the role session, so an action taken with
    that role cannot be tied back to a single agent.

    Every role an agent can run under counts, not only the working draft's.
    GetAgent returns the draft, but an agent version is an immutable snapshot
    that keeps the role it was cut with, and an alias routes invocations at a
    specific version — so a deployed version can still hold a role the draft no
    longer has, and sharing it is the same exposure. Only versions an alias
    routes to are considered, since a version no alias points at cannot be
    invoked. An alias routing at DRAFT resolves to the draft role already read.

    Sharing is judged against the whole account inventory, so the verdict is only
    as complete as that inventory. Dedication cannot be asserted while any part of
    the picture is missing — an unlisted Region, an agent whose own role could
    not be read, or an agent whose deployed versions could not be listed may hold
    the same role. A role already seen on two agents is shared whatever else is
    missing, so FAIL survives an incomplete inventory.

    A scan scoped with ``--resource-arn`` narrows which agents are REPORTED on, not
    which agents count towards sharing: the role index is built from the complete
    account inventory, so selecting one of two agents that share a role still FAILs.

    - PASS: No role this agent holds is used by any other agent, every Region's
      agent inventory was listed, every discovered agent's role was readable, and
      every agent's deployed versions were listed.
    - FAIL: Two or more agents hold the same role, on the draft or on a deployed
      version; the other agents holding it are named in the message, and the
      version is named when the sharing is through one.
    - MANUAL: This agent's own execution role could not be retrieved from
      GetAgent; or its roles look dedicated but another agent's role or deployed
      versions are unknown, or a Region could not be listed; or ListAgents failed
      for a Region, which therefore contributed no agents at all.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        incomplete_regions = sorted(bedrock_agent_client.agents_scan_errors)
        for region, error in sorted(bedrock_agent_client.agents_scan_errors.items()):
            report = Check_Report_AWS(
                metadata=self.metadata(), resource={"region": region}
            )
            report.region = region
            report.resource_id = "agent/unknown"
            report.resource_arn = f"arn:{bedrock_agent_client.audited_partition}:bedrock:{region}:{bedrock_agent_client.audited_account}:agent/unknown"
            report.status = "MANUAL"
            report.status_extended = f"Bedrock Agents could not be listed in region {region} ({error}); verify manually that no execution role is shared between agents."
            findings.append(report)

        # Keyed on agent ARN, not name, so two same-named agents still count
        # twice. An agent is indexed under every role it holds, because a
        # deployed version keeps the role it was cut with: sharing through a
        # version is the same exposure as sharing through the draft. Indexed over
        # all_agents, not the filtered agents; findings are emitted from the
        # filtered set below.
        agents_by_role = {}
        unresolved_agents = []
        for agent in bedrock_agent_client.all_agents.values():
            entry = (agent.arn, agent.name or agent.id)
            for role_arn in self._roles_held_by(agent):
                if entry not in agents_by_role.setdefault(role_arn, []):
                    agents_by_role[role_arn].append(entry)
            # Both gaps are recorded, not just the first: an agent can have an
            # unreadable draft role and an unlistable version inventory at once,
            # and each independently keeps another agent from being called
            # dedicated.
            if not agent.detail_retrieved or not agent.role_arn:
                unresolved_agents.append(
                    f"the execution role of {agent.name or agent.id}"
                )
            if not agent.versions_listed:
                unresolved_agents.append(
                    f"deployed versions of {agent.name or agent.id}"
                )

        # Dedication can only be asserted from a complete picture: an unlisted
        # Region, an agent whose role could not be read, or an agent whose
        # deployed versions could not be listed may hold the same role.
        incomplete = sorted(unresolved_agents) + [
            f"agents in region {region}" for region in incomplete_regions
        ]

        for agent in bedrock_agent_client.agents.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=agent)
            name = agent.name or agent.id

            if not agent.detail_retrieved or not agent.role_arn:
                report.status = "MANUAL"
                report.status_extended = f"Bedrock Agent {name} execution role could not be retrieved in region {agent.region}; verify manually that no other agent shares it."
                findings.append(report)
                continue

            # Any role this agent holds, on the draft or on a deployed version,
            # is a finding when another agent holds it too. Reported on the
            # lowest-sorted shared role for determinism across scans.
            shared_roles = sorted(
                role_arn
                for role_arn in self._roles_held_by(agent)
                if len(agents_by_role.get(role_arn, [])) >= SHARED_ROLE_AGENT_COUNT
            )
            if shared_roles:
                role_arn = shared_roles[0]
                others = sorted(
                    other_name
                    for other_arn, other_name in agents_by_role[role_arn]
                    if other_arn != agent.arn
                )
                through = (
                    ""
                    if role_arn == agent.role_arn
                    else f" through deployed version {sorted(version for version, version_role in agent.version_role_arns.items() if version_role == role_arn)[0]}"
                )
                report.status = "FAIL"
                report.status_extended = f"Bedrock Agent {name} shares execution role {role_arn}{through} with {', '.join(others)} in region {agent.region}, so each agent inherits the union of their permissions and CloudTrail cannot attribute an action to one of them."
            elif incomplete:
                report.status = "MANUAL"
                # Each entry already reads as its own subject, because they are
                # not all roles: an entry is an agent whose role is unknown, the
                # deployed versions of an agent, or the agents of a Region that
                # could not be listed.
                report.status_extended = f"Bedrock Agent {name} execution role is used by no other agent whose role could be read in region {agent.region}, but {', '.join(incomplete)} could not be read; verify manually that none of them shares it."
            else:
                report.status = "PASS"
                report.status_extended = f"Bedrock Agent {name} has a dedicated execution role in region {agent.region}."
            findings.append(report)

        return findings

    def _roles_held_by(self, agent) -> set:
        """Collect every execution role an agent can run under.

        Args:
            agent: The Bedrock Agent to inspect.

        Returns:
            The working draft's role plus the role of each deployed version an
            alias routes to, skipping any that could not be read.
        """
        roles = set()
        if agent.detail_retrieved and agent.role_arn:
            roles.add(agent.role_arn)
        roles.update(
            role_arn for role_arn in agent.version_role_arns.values() if role_arn
        )
        return roles
