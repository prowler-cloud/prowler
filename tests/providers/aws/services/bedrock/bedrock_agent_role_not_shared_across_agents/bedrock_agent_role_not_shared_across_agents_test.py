from unittest import mock

import botocore
from botocore.exceptions import ClientError
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
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


def _agent_mock(agents, fail_get_for=()):
    """Build a _make_api_call replacement returning the given agents.

    Args:
        agents: list of (agentId, agentName, roleArn) tuples.
        fail_get_for: agent ids whose GetAgent call must raise.
    """

    def _mock(self, operation_name, kwarg):
        if operation_name in _UNUSED_OPERATIONS:
            return {}
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
    if operation_name == "ListAgents":
        return {"agentSummaries": []}
    return make_api_call(self, operation_name, kwarg)


def _mock_unsupported_region(self, operation_name, kwarg):
    """The API is not available in the audited region."""
    if operation_name in _UNUSED_OPERATIONS:
        return {}
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
        """An agent excluded from the index cannot make another agent's role look shared."""
        result = self._run()
        assert len(result) == 2
        by_id = {report.resource_id: report for report in result}
        assert by_id[AGENT_B_ID].status == "MANUAL"
        # Only one readable agent uses the role, so it is not provably shared.
        assert by_id[AGENT_A_ID].status == "PASS"
