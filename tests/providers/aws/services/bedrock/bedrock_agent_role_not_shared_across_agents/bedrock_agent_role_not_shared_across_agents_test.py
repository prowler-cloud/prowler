from unittest import mock

import botocore
from botocore.exceptions import ClientError
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    AWS_REGION_US_WEST_2,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call

AGENT_A_ID = "test-agent-a"
AGENT_A_NAME = "agent-alpha"
AGENT_A_ARN = (
    f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:agent/{AGENT_A_ID}"
)
AGENT_B_ID = "test-agent-b"
AGENT_B_NAME = "agent-bravo"
AGENT_B_ARN = (
    f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:agent/{AGENT_B_ID}"
)
AGENT_C_ID = "test-agent-c"
AGENT_C_NAME = "agent-charlie"

SHARED_ROLE_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/SharedAgentRole"
ROLE_A_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/AgentAlphaRole"
ROLE_B_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/AgentBravoRole"

# Operations the BedrockAgent constructor calls that these tests do not exercise.
_UNUSED_OPERATIONS = (
    "ListPrompts",
    "GetPrompt",
    "ListTagsForResource",
    "ListKnowledgeBases",
    "ListDataSources",
    "GetDataSource",
)

# These scenarios describe agents with no alias, so no version is deployed and
# the draft role is the only one in play. ListAgentAliases is stubbed empty
# rather than left to moto, which does not implement it: an unstubbed call would
# leave the version inventory unread and correctly downgrade every PASS to
# MANUAL, masking what these tests are actually asserting.
_NO_ALIASES = {"agentAliasSummaries": []}


def _agent_mock(agents, fail_get_for=()):
    """Build a _make_api_call replacement returning the given agents.

    Args:
        agents: list of (agentId, agentName, roleArn) tuples.
        fail_get_for: agent ids whose GetAgent call must raise.
    """

    def _mock(self, operation_name, kwarg):
        if operation_name in _UNUSED_OPERATIONS:
            return {}
        if operation_name == "ListAgentAliases":
            return _NO_ALIASES
        if operation_name == "ListAgents":
            return {
                "agentSummaries": [
                    {
                        "agentId": agent_id,
                        "agentName": agent_name,
                        "agentStatus": "PREPARED",
                    }
                    for agent_id, agent_name, _ in agents
                ]
            }
        if operation_name == "GetAgent":
            agent_id = kwarg["agentId"]
            if agent_id in fail_get_for:
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                    operation_name,
                )
            # GetAgent nests its payload under a top-level agent key.
            for candidate_id, agent_name, role_arn in agents:
                if candidate_id == agent_id:
                    agent = {
                        "agentId": candidate_id,
                        "agentName": agent_name,
                        "agentStatus": "PREPARED",
                    }
                    if role_arn is not None:
                        agent["agentResourceRoleArn"] = role_arn
                    return {"agent": agent}
            return {"agent": {}}
        return make_api_call(self, operation_name, kwarg)

    return _mock


_mock_dedicated_roles = _agent_mock(
    [
        (AGENT_A_ID, AGENT_A_NAME, ROLE_A_ARN),
        (AGENT_B_ID, AGENT_B_NAME, ROLE_B_ARN),
    ]
)
_mock_shared_role = _agent_mock(
    [
        (AGENT_A_ID, AGENT_A_NAME, SHARED_ROLE_ARN),
        (AGENT_B_ID, AGENT_B_NAME, SHARED_ROLE_ARN),
    ]
)
_mock_shared_role_three_agents = _agent_mock(
    [
        (AGENT_A_ID, AGENT_A_NAME, SHARED_ROLE_ARN),
        (AGENT_B_ID, AGENT_B_NAME, SHARED_ROLE_ARN),
        (AGENT_C_ID, AGENT_C_NAME, SHARED_ROLE_ARN),
    ]
)
_mock_single_agent = _agent_mock([(AGENT_A_ID, AGENT_A_NAME, ROLE_A_ARN)])
_mock_role_missing = _agent_mock([(AGENT_A_ID, AGENT_A_NAME, None)])
_mock_get_agent_fails = _agent_mock(
    [(AGENT_A_ID, AGENT_A_NAME, ROLE_A_ARN)], fail_get_for=(AGENT_A_ID,)
)
# One agent's role is unreadable, so it must not count toward the other's share.
_mock_one_unreadable_one_readable = _agent_mock(
    [
        (AGENT_A_ID, AGENT_A_NAME, SHARED_ROLE_ARN),
        (AGENT_B_ID, AGENT_B_NAME, SHARED_ROLE_ARN),
    ],
    fail_get_for=(AGENT_B_ID,),
)


def _mock_empty(self, operation_name, kwarg):
    """No agents at all."""
    if operation_name in _UNUSED_OPERATIONS:
        return {}
    if operation_name == "ListAgentAliases":
        return _NO_ALIASES
    if operation_name == "ListAgents":
        return {"agentSummaries": []}
    return make_api_call(self, operation_name, kwarg)


def _mock_unsupported_region(self, operation_name, kwarg):
    """The API is not available in the audited region."""
    if operation_name in _UNUSED_OPERATIONS:
        return {}
    if operation_name == "ListAgentAliases":
        return _NO_ALIASES
    if operation_name == "ListAgents":
        raise ClientError(
            {
                "Error": {
                    "Code": "ValidationException",
                    "Message": "Bedrock Agent is not supported in this region.",
                }
            },
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


def _inventory_mock(agents):
    """Build a stub for one exhaustive-matrix inventory.

    Args:
        agents: list of (name, roleArn, retrieved) tuples. retrieved=False makes
            GetAgent raise for that agent.
    """
    rows = [(name, name, role) for name, role, _ in agents]
    fail = tuple(name for name, _, retrieved in agents if not retrieved)
    return _agent_mock(rows, fail_get_for=fail)


def _mock_list_agents_denied(self, operation_name, kwarg):
    """ListAgents is denied, so the region's agents are unknown."""
    if operation_name in _UNUSED_OPERATIONS:
        return {}
    if operation_name == "ListAgentAliases":
        return _NO_ALIASES
    if operation_name == "ListAgents":
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


def _mock_dedicated_role_with_partial_inventory(self, operation_name, kwarg):
    """us-east-1 lists one agent; us-west-2's ListAgents is denied.

    The listed agent's role is used by no other KNOWN agent, but an unlisted
    Region could hold one sharing it, so PASS must not be asserted.
    """
    if operation_name in _UNUSED_OPERATIONS:
        return {}
    if operation_name == "ListAgentAliases":
        return _NO_ALIASES
    region = self.meta.region_name
    if operation_name == "ListAgents":
        if region == AWS_REGION_US_EAST_1:
            return {
                "agentSummaries": [
                    {
                        "agentId": AGENT_A_ID,
                        "agentName": AGENT_A_NAME,
                        "agentStatus": "PREPARED",
                    }
                ]
            }
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            operation_name,
        )
    if operation_name == "GetAgent":
        return {
            "agent": {
                "agentId": AGENT_A_ID,
                "agentName": AGENT_A_NAME,
                "agentStatus": "PREPARED",
                "agentResourceRoleArn": ROLE_A_ARN,
            }
        }
    return make_api_call(self, operation_name, kwarg)


class Test_bedrock_agent_role_not_shared_across_agents:
    """Unit tests for the bedrock_agent_role_not_shared_across_agents check."""

    def _run(self):
        """Import the service + check under the active mocks and execute."""
        from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_agent_role_not_shared_across_agents.bedrock_agent_role_not_shared_across_agents.bedrock_agent_client",
                new=BedrockAgent(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_agent_role_not_shared_across_agents.bedrock_agent_role_not_shared_across_agents import (
                bedrock_agent_role_not_shared_across_agents,
            )

            return bedrock_agent_role_not_shared_across_agents().execute()

    def _run_multi_region(self):
        """Same as _run but with two Regions in scope."""
        from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_US_WEST_2]
        )
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_agent_role_not_shared_across_agents.bedrock_agent_role_not_shared_across_agents.bedrock_agent_client",
                new=BedrockAgent(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_agent_role_not_shared_across_agents.bedrock_agent_role_not_shared_across_agents import (
                bedrock_agent_role_not_shared_across_agents,
            )

            return bedrock_agent_role_not_shared_across_agents().execute()

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_empty)
    @mock_aws
    def test_no_resources(self):
        """No resources means no findings, not a spurious FAIL."""
        assert self._run() == []

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_unsupported_region
    )
    @mock_aws
    def test_region_not_supported(self):
        """A ValidationException from the region must not raise; it yields no findings."""
        assert self._run() == []

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_single_agent)
    @mock_aws
    def test_single_agent_passes(self):
        """The only agent in the account cannot be sharing its role."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == AGENT_A_ID
        assert result[0].resource_arn == AGENT_A_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
        assert (
            result[0].status_extended
            == f"Bedrock Agent {AGENT_A_NAME} has a dedicated execution role in region {AWS_REGION_US_EAST_1}."
        )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_dedicated_roles)
    @mock_aws
    def test_distinct_roles_pass(self):
        """Two agents with distinct roles are both compliant."""
        result = self._run()
        assert len(result) == 2
        assert {report.status for report in result} == {"PASS"}

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_shared_role)
    @mock_aws
    def test_shared_role_fails_for_both_agents(self):
        """A role used by two agents fails for each of them, naming the other."""
        result = self._run()
        assert len(result) == 2
        assert {report.status for report in result} == {"FAIL"}
        by_id = {report.resource_id: report for report in result}
        assert SHARED_ROLE_ARN in by_id[AGENT_A_ID].status_extended
        assert AGENT_B_NAME in by_id[AGENT_A_ID].status_extended
        assert AGENT_A_NAME in by_id[AGENT_B_ID].status_extended
        assert "cannot attribute an action" in by_id[AGENT_A_ID].status_extended

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_shared_role_three_agents
    )
    @mock_aws
    def test_shared_role_names_others_sorted(self):
        """The other sharing agents are listed in sorted order for determinism."""
        result = self._run()
        assert len(result) == 3
        assert {report.status for report in result} == {"FAIL"}
        by_id = {report.resource_id: report for report in result}
        assert (
            f"with {AGENT_B_NAME}, {AGENT_C_NAME} in region"
            in by_id[AGENT_A_ID].status_extended
        )
        assert (
            f"with {AGENT_A_NAME}, {AGENT_C_NAME} in region"
            in by_id[AGENT_B_ID].status_extended
        )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_role_missing)
    @mock_aws
    def test_role_absent_is_manual_not_pass(self):
        """An agent whose GetAgent returned no role must not be reported as compliant."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be retrieved" in result[0].status_extended

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_get_agent_fails)
    @mock_aws
    def test_get_agent_failure_is_manual_not_pass(self):
        """A failed GetAgent must not be reported as compliant."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be retrieved" in result[0].status_extended

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock_one_unreadable_one_readable,
    )
    @mock_aws
    def test_unreadable_agent_does_not_inflate_share_count(self):
        """An excluded agent must neither manufacture a FAIL nor allow a PASS.

        The unreadable agent is kept out of the share index, so the readable agent
        is not reported as sharing. But its role is unknown and could be the same
        one, so the readable agent cannot be asserted dedicated either: both are
        MANUAL, and neither is FAIL.
        """
        result = self._run()
        assert len(result) == 2
        by_id = {report.resource_id: report for report in result}
        assert by_id[AGENT_B_ID].status == "MANUAL"
        assert by_id[AGENT_A_ID].status == "MANUAL"
        assert "could not be read" in by_id[AGENT_A_ID].status_extended
        # The entry names what could not be read, so the sentence stays
        # grammatical for a role, a version set, or a Region alike.
        assert (
            f"the execution role of {AGENT_B_NAME}" in by_id[AGENT_A_ID].status_extended
        )
        assert {report.status for report in result} == {"MANUAL"}

    def test_every_inventory_shape_resolves_correctly(self):
        """Exhaust the decision space instead of sampling it.

        Bedrock Agents cannot be created in every account (the service refuses new
        agents for accounts without prior usage), so this check's behaviour is
        pinned by enumerating every inventory of up to three agents over the cross
        product of {role A, role B, no role} x {readable, unreadable}, and
        asserting the verdict for each agent. A role counts as shared only when two
        or more READABLE agents hold it.

        Each case is driven through the real BedrockAgent service so a renamed
        service attribute breaks the test rather than passing silently.
        """
        from itertools import product

        states = [
            (ROLE_A_ARN, True),
            (ROLE_B_ARN, True),
            (None, True),
            (ROLE_A_ARN, False),
        ]

        checked = 0
        for size in (1, 2, 3):
            for combo in product(states, repeat=size):
                agents = [
                    (f"agent-{index}", role, retrieved)
                    for index, (role, retrieved) in enumerate(combo)
                ]

                readable_per_role = {}
                for _, role, retrieved in agents:
                    if retrieved and role:
                        readable_per_role[role] = readable_per_role.get(role, 0) + 1
                # Any agent whose own role could not be read leaves the picture
                # incomplete, so no other agent can be asserted dedicated. A role
                # already seen twice is shared regardless.
                any_unresolved = any(
                    not retrieved or not role for _, role, retrieved in agents
                )
                expected = sorted(
                    (
                        "MANUAL"
                        if not retrieved or not role
                        else (
                            "FAIL"
                            if readable_per_role[role] >= 2
                            else ("MANUAL" if any_unresolved else "PASS")
                        )
                    )
                    for _, role, retrieved in agents
                )

                with mock.patch(
                    "botocore.client.BaseClient._make_api_call",
                    new=_inventory_mock(agents),
                ):
                    with mock_aws():
                        result = self._run()

                assert len(result) == size, combo
                assert sorted(report.status for report in result) == expected, combo
                assert all(
                    report.status_extended.endswith(".") for report in result
                ), combo
                checked += 1

        # 4 + 16 + 64 inventories.
        assert checked == 84

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_list_agents_denied
    )
    @mock_aws
    def test_list_agents_denied_is_manual_not_silence(self):
        """A denied ListAgents must report MANUAL for the region, not vanish."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].resource_id == "agent/unknown"
        assert "could not be listed" in result[0].status_extended
        assert "AccessDeniedException" in result[0].status_extended
        assert result[0].status_extended.endswith(".")

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock_dedicated_role_with_partial_inventory,
    )
    @mock_aws
    def test_dedicated_role_is_manual_when_inventory_incomplete(self):
        """A seemingly dedicated role cannot be asserted from a partial inventory.

        One Region lists an agent whose role no other known agent uses, while
        another Region's ListAgents fails. An unlisted Region could hold an agent
        sharing that role, so the verdict is MANUAL rather than PASS.
        """
        result = self._run_multi_region()
        by_status = {}
        for report in result:
            by_status.setdefault(report.status, []).append(report)
        assert "PASS" not in by_status, [r.status_extended for r in result]
        assert len(by_status["MANUAL"]) == 2
        agent_report = [
            r for r in by_status["MANUAL"] if r.resource_id != "agent/unknown"
        ]
        assert len(agent_report) == 1
        assert "agents in region" in agent_report[0].status_extended
        assert all(r.status_extended.endswith(".") for r in result)

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_agent_mock(
            [
                (AGENT_A_ID, AGENT_A_NAME, ROLE_A_ARN),
                (AGENT_B_ID, AGENT_B_NAME, ROLE_B_ARN),
            ],
            fail_get_for=(AGENT_B_ID,),
        ),
    )
    @mock_aws
    def test_unresolved_role_blocks_pass_for_a_distinct_role(self):
        """One agent's unreadable role prevents asserting another's dedication.

        Agent A holds a role no other *readable* agent uses, so the old logic
        returned PASS. Agent B's role could not be retrieved and may be the same
        one, so PASS would be an assertion the data does not support.
        """
        result = self._run()
        assert len(result) == 2
        by_id = {report.resource_id: report for report in result}
        assert by_id[AGENT_B_ID].status == "MANUAL"
        assert by_id[AGENT_A_ID].status == "MANUAL"
        assert AGENT_B_NAME in by_id[AGENT_A_ID].status_extended
        assert "PASS" not in {report.status for report in result}


class Test_scoped_scan_still_sees_the_sharing:
    """A --resource-arn scoped scan must not turn a shared role into a PASS.

    Collectors apply is_resource_filtered at COLLECTION time, so
    bedrock_agent_client.agents holds only the agents the operator selected.
    Whether a role is shared is a property of every agent that holds it, so an
    index built from the filtered set cannot see the agent that proves the
    violation -- and an operator filter is not a scan error, so nothing marks the
    inventory incomplete either. The check therefore aggregates over all_agents
    and filters only when emitting findings.
    """

    def _run_scoped(self, audit_resources):
        """Execute the check with a scan scoped to the given resource ARNs."""
        from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        aws_provider._audit_resources = audit_resources
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            service = BedrockAgent(aws_provider)
        with mock.patch(
            "prowler.providers.aws.services.bedrock."
            "bedrock_agent_role_not_shared_across_agents."
            "bedrock_agent_role_not_shared_across_agents.bedrock_agent_client",
            new=service,
        ):
            from prowler.providers.aws.services.bedrock.bedrock_agent_role_not_shared_across_agents.bedrock_agent_role_not_shared_across_agents import (
                bedrock_agent_role_not_shared_across_agents,
            )

            return service, bedrock_agent_role_not_shared_across_agents().execute()

    @mock_aws
    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_agent_mock(
            [
                (AGENT_A_ID, AGENT_A_NAME, SHARED_ROLE_ARN),
                (AGENT_B_ID, AGENT_B_NAME, SHARED_ROLE_ARN),
            ]
        ),
    )
    def test_selecting_one_of_two_sharing_agents_still_fails(self):
        """The unselected agent is what proves the role is shared.

        Only agent A is in scope, so exactly one finding is emitted -- but agent
        B, filtered out of the report, still holds the same role, so agent A's
        role is not dedicated. Reporting PASS here was the reproducible false
        PASS a scoped scan produced.
        """
        service, result = self._run_scoped([AGENT_A_ARN])

        # The report set is narrowed; the role index is not.
        assert list(service.agents) == [AGENT_A_ARN]
        assert sorted(service.all_agents) == sorted([AGENT_A_ARN, AGENT_B_ARN])

        assert len(result) == 1
        assert result[0].resource_id == AGENT_A_ID
        assert result[0].resource_arn == AGENT_A_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].status == "FAIL"
        assert SHARED_ROLE_ARN in result[0].status_extended
        # The out-of-scope agent is still named, because it is the evidence.
        assert AGENT_B_NAME in result[0].status_extended

    @mock_aws
    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_agent_mock(
            [
                (AGENT_A_ID, AGENT_A_NAME, ROLE_A_ARN),
                (AGENT_B_ID, AGENT_B_NAME, ROLE_B_ARN),
            ]
        ),
    )
    def test_scoped_scan_on_a_genuinely_dedicated_role_passes(self):
        """Completeness must not manufacture a FAIL either.

        Aggregating over the whole account is only correct if a genuinely
        dedicated role still passes when the scan is scoped.
        """
        service, result = self._run_scoped([AGENT_A_ARN])

        assert list(service.agents) == [AGENT_A_ARN]
        assert len(service.all_agents) == 2
        assert len(result) == 1
        assert result[0].resource_id == AGENT_A_ID
        assert result[0].status == "PASS"
        assert "has a dedicated execution role" in result[0].status_extended

    @mock_aws
    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_agent_mock(
            [
                (AGENT_A_ID, AGENT_A_NAME, SHARED_ROLE_ARN),
                (AGENT_B_ID, AGENT_B_NAME, SHARED_ROLE_ARN),
            ]
        ),
    )
    def test_unscoped_scan_is_unchanged(self):
        """With no filter, every agent is both aggregated and reported."""
        service, result = self._run_scoped(None)

        assert sorted(service.agents) == sorted(service.all_agents)
        assert len(result) == 2
        assert {report.status for report in result} == {"FAIL"}
