"""Tests that a role shared through a deployed agent version is still reported.

GetAgent returns only the working draft. An agent version is an immutable
snapshot that keeps the role it was cut with, and an alias routes invocations at
a specific version, so two agents whose drafts hold distinct roles can still be
invoking one shared role in production. Judging the draft alone reports that as
compliant.
"""

from unittest import mock

import botocore
import pytest
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
AGENT_B_ID = "test-agent-b"
AGENT_B_NAME = "agent-bravo"

DRAFT_A_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/AgentAlphaDraftRole"
DRAFT_B_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/AgentBravoDraftRole"
SHARED_VERSION_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/SharedVersionRole"
DEDICATED_VERSION_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/AlphaVersionRole"

# Collectors the BedrockAgent constructor runs that these tests do not exercise.
_UNUSED_OPERATIONS = (
    "ListPrompts",
    "GetPrompt",
    "ListTagsForResource",
    "ListKnowledgeBases",
    "ListDataSources",
    "GetDataSource",
)

DRAFT_ROLES = {AGENT_A_ID: DRAFT_A_ARN, AGENT_B_ID: DRAFT_B_ARN}


def _mock(
    version_roles,
    routed_version="3",
    fail_list_aliases=(),
    fail_get_version=(),
    route_draft=False,
    no_aliases=(),
    alias_status="PREPARED",
    alias_invocation_state=None,
    aliases=None,
    draft_roles=DRAFT_ROLES,
):
    """Build a _make_api_call replacement for a two-agent account.

    Args:
        version_roles: agent id -> role ARN its deployed version was cut with.
        routed_version: the version each alias routes to.
        fail_list_aliases: agent ids whose ListAgentAliases must raise.
        fail_get_version: agent ids whose GetAgentVersion must raise.
        route_draft: route the alias at DRAFT instead of a numbered version.
        no_aliases: agent ids that have no alias at all.
        alias_status: agentAliasStatus each alias reports.
        alias_invocation_state: aliasInvocationState each alias reports; omitted
            from the response entirely when None, which is what the API does for
            an alias never set to reject.
        aliases: agentAliasSummaries to return instead of building one alias.
        draft_roles: agent id -> role ARN returned by GetAgent.
    """

    def _call(self, operation_name, kwarg):
        if operation_name in _UNUSED_OPERATIONS:
            return {}
        if operation_name == "ListAgents":
            return {
                "agentSummaries": [
                    {
                        "agentId": AGENT_A_ID,
                        "agentName": AGENT_A_NAME,
                        "agentStatus": "PREPARED",
                    },
                    {
                        "agentId": AGENT_B_ID,
                        "agentName": AGENT_B_NAME,
                        "agentStatus": "PREPARED",
                    },
                ]
            }
        if operation_name == "GetAgent":
            agent_id = kwarg["agentId"]
            return {
                "agent": {
                    "agentId": agent_id,
                    "agentName": agent_id,
                    "agentStatus": "PREPARED",
                    "agentResourceRoleArn": draft_roles[agent_id],
                }
            }
        if operation_name == "ListAgentAliases":
            agent_id = kwarg["agentId"]
            if agent_id in fail_list_aliases:
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                    operation_name,
                )
            if aliases is not None:
                return {"agentAliasSummaries": aliases}
            if agent_id in no_aliases:
                return {"agentAliasSummaries": []}
            alias = {
                "agentAliasId": "alias-1",
                "agentAliasName": "production",
                "agentAliasStatus": alias_status,
                "routingConfiguration": [
                    {"agentVersion": "DRAFT" if route_draft else routed_version}
                ],
            }
            if alias_invocation_state is not None:
                alias["aliasInvocationState"] = alias_invocation_state
            return {"agentAliasSummaries": [alias]}
        if operation_name == "GetAgentVersion":
            agent_id = kwarg["agentId"]
            if agent_id in fail_get_version:
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                    operation_name,
                )
            return {
                "agentVersion": {
                    "agentId": agent_id,
                    "agentName": agent_id,
                    "version": kwarg["agentVersion"],
                    "agentStatus": "PREPARED",
                    "agentResourceRoleArn": version_roles[agent_id],
                }
            }
        return make_api_call(self, operation_name, kwarg)

    return _call


def _run(stub):
    """Import the service and check under the stub and execute."""
    from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent

    check_name = "bedrock_agent_role_not_shared_across_agents"
    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    with (
        mock.patch("botocore.client.BaseClient._make_api_call", new=stub),
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
    ):
        service = BedrockAgent(aws_provider)
    with mock.patch(
        f"prowler.providers.aws.services.bedrock.{check_name}.{check_name}.bedrock_agent_client",
        new=service,
    ):
        module = __import__(
            f"prowler.providers.aws.services.bedrock.{check_name}.{check_name}",
            fromlist=[check_name],
        )
        return service, getattr(module, check_name)().execute()


class Test_agent_version_roles:
    """Tests for sharing judged across the draft and every routed version."""

    @mock_aws
    def test_shared_version_role_fails_despite_distinct_drafts(self):
        """Distinct drafts do not make two agents dedicated.

        Both agents' aliases route at a version cut with one shared role, so
        both are invoking it in production. Judging the draft alone would call
        this compliant.
        """
        service, results = _run(
            _mock({AGENT_A_ID: SHARED_VERSION_ARN, AGENT_B_ID: SHARED_VERSION_ARN})
        )

        for agent in service.agents.values():
            assert agent.versions_listed is True
            assert agent.version_role_arns == {"3": SHARED_VERSION_ARN}

        assert len(results) == 2
        assert {report.status for report in results} == {"FAIL"}
        for report in results:
            assert SHARED_VERSION_ARN in report.status_extended
            # The message names the version, so the reader knows the draft is
            # not where the sharing lives.
            assert "through deployed version 3" in report.status_extended
            assert report.status_extended.endswith(".")

    @mock_aws
    def test_distinct_version_roles_pass(self):
        """Distinct roles on both the draft and the deployed version comply."""
        _, results = _run(
            _mock(
                {
                    AGENT_A_ID: DEDICATED_VERSION_ARN,
                    AGENT_B_ID: f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/BravoVersionRole",
                }
            )
        )

        assert len(results) == 2
        assert {report.status for report in results} == {"PASS"}

    @mock_aws
    def test_draft_sharing_still_names_no_version(self):
        """Sharing on the draft is reported without a version attribution."""
        stub = _mock(
            {
                AGENT_A_ID: DEDICATED_VERSION_ARN,
                AGENT_B_ID: f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/BravoVersionRole",
            }
        )

        def _shared_draft(self, operation_name, kwarg):
            if operation_name == "GetAgent":
                return {
                    "agent": {
                        "agentId": kwarg["agentId"],
                        "agentName": kwarg["agentId"],
                        "agentStatus": "PREPARED",
                        "agentResourceRoleArn": DRAFT_A_ARN,
                    }
                }
            return stub(self, operation_name, kwarg)

        _, results = _run(_shared_draft)

        assert len(results) == 2
        assert {report.status for report in results} == {"FAIL"}
        for report in results:
            assert DRAFT_A_ARN in report.status_extended
            assert "through deployed version" not in report.status_extended

    @mock_aws
    def test_alias_routing_at_draft_needs_no_version_call(self):
        """DRAFT resolves to the role GetAgent already returned."""
        service, results = _run(
            _mock(
                {AGENT_A_ID: SHARED_VERSION_ARN, AGENT_B_ID: SHARED_VERSION_ARN},
                route_draft=True,
            )
        )

        for agent in service.agents.values():
            assert agent.versions_listed is True
            assert agent.version_role_arns == {}

        assert len(results) == 2
        assert {report.status for report in results} == {"PASS"}

    @mock_aws
    def test_agent_without_an_alias_deploys_no_version(self):
        """No alias means no version is reachable, so the draft is the verdict."""
        service, results = _run(
            _mock(
                {AGENT_A_ID: SHARED_VERSION_ARN, AGENT_B_ID: SHARED_VERSION_ARN},
                no_aliases=(AGENT_A_ID, AGENT_B_ID),
            )
        )

        for agent in service.agents.values():
            assert agent.versions_listed is True
            assert agent.version_role_arns == {}

        assert {report.status for report in results} == {"PASS"}

    @mock_aws
    def test_unlistable_aliases_block_pass(self):
        """An unread version inventory may hold the same role, so PASS is unsafe."""
        service, results = _run(
            _mock(
                {AGENT_A_ID: DEDICATED_VERSION_ARN, AGENT_B_ID: DEDICATED_VERSION_ARN},
                fail_list_aliases=(AGENT_B_ID,),
            )
        )

        agent_b = next(a for a in service.agents.values() if a.id == AGENT_B_ID)
        assert agent_b.versions_listed is False
        assert agent_b.versions_error == "AccessDeniedException"

        assert "PASS" not in {report.status for report in results}
        assert {report.status for report in results} == {"MANUAL"}
        assert any(
            "deployed versions of" in report.status_extended for report in results
        )

    @mock_aws
    def test_unreadable_version_blocks_pass(self):
        """A failed GetAgentVersion leaves that version's role unknown."""
        service, results = _run(
            _mock(
                {AGENT_A_ID: DEDICATED_VERSION_ARN, AGENT_B_ID: DEDICATED_VERSION_ARN},
                fail_get_version=(AGENT_A_ID,),
            )
        )

        agent_a = next(a for a in service.agents.values() if a.id == AGENT_A_ID)
        assert agent_a.versions_listed is False

        assert "PASS" not in {report.status for report in results}

    @mock_aws
    def test_shared_version_role_outranks_an_incomplete_inventory(self):
        """A role seen on two agents is shared whatever else is missing.

        Both agents route at two versions and the second version is unreadable,
        so the inventory is incomplete and the read half already shows the role
        on both. A partial answer must not downgrade a definite finding, so FAIL
        stands rather than MANUAL.
        """

        def _two_versions_one_unreadable(self, operation_name, kwarg):
            if operation_name == "ListAgentAliases":
                return {
                    "agentAliasSummaries": [
                        {
                            "agentAliasId": "alias-1",
                            "agentAliasName": "production",
                            "agentAliasStatus": "PREPARED",
                            "routingConfiguration": [
                                {"agentVersion": "2"},
                                {"agentVersion": "3"},
                            ],
                        }
                    ]
                }
            if operation_name == "GetAgentVersion" and kwarg["agentVersion"] == "3":
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                    operation_name,
                )
            return _mock(
                {AGENT_A_ID: SHARED_VERSION_ARN, AGENT_B_ID: SHARED_VERSION_ARN}
            )(self, operation_name, kwarg)

        service, results = _run(_two_versions_one_unreadable)

        for agent in service.agents.values():
            assert agent.versions_listed is False, "the inventory must be incomplete"
            assert agent.version_role_arns == {"2": SHARED_VERSION_ARN}

        assert {report.status for report in results} == {"FAIL"}
        for report in results:
            assert "through deployed version 2" in report.status_extended


class Test_alias_must_be_invocable:
    """A version only an unreachable alias routes to is not live exposure.

    Widening the audit from the working draft to every routed version closes a
    false PASS and opens the symmetric false FAIL: an alias that cannot invoke
    the version it points at contributes no exposure, so the role on that
    version must not count as shared. Both state fields come from
    ListAgentAliases -- `aliasInvocationState` is ACCEPT_INVOCATIONS |
    REJECT_INVOCATIONS, `agentAliasStatus` is CREATING | PREPARED | FAILED |
    UPDATING | DELETING | DISSOCIATED.
    """

    @mock_aws
    def test_reject_invocations_alias_does_not_share_its_version_role(self):
        """An alias set to REJECT_INVOCATIONS cannot invoke the routed version.

        Both agents' aliases route at a version cut with one shared role, so
        judging routing alone reports FAIL -- but neither alias will accept an
        invocation, so nothing is running under that role.
        """
        service, results = _run(
            _mock(
                {AGENT_A_ID: SHARED_VERSION_ARN, AGENT_B_ID: SHARED_VERSION_ARN},
                alias_invocation_state="REJECT_INVOCATIONS",
            )
        )

        for agent in service.all_agents.values():
            assert agent.versions_listed is True, "the aliases WERE listed"
            assert agent.version_role_arns == {}, "a rejecting alias routes nothing"

        assert len(results) == 2
        assert {report.status for report in results} == {"PASS"}
        for report in results:
            assert "has a dedicated execution role" in report.status_extended

    @pytest.mark.parametrize("alias_status", ["FAILED", "DELETING", "DISSOCIATED"])
    @mock_aws
    def test_terminal_alias_status_does_not_share_its_version_role(self, alias_status):
        """A failed, deleting or dissociated alias routes no live invocation."""
        service, results = _run(
            _mock(
                {AGENT_A_ID: SHARED_VERSION_ARN, AGENT_B_ID: SHARED_VERSION_ARN},
                alias_status=alias_status,
            )
        )

        for agent in service.all_agents.values():
            assert agent.version_role_arns == {}

        assert len(results) == 2
        assert {report.status for report in results} == {"PASS"}

    @pytest.mark.parametrize("alias_status", ["CREATING", "UPDATING"])
    @mock_aws
    def test_in_flight_alias_status_makes_version_inventory_incomplete(
        self, alias_status
    ):
        """CREATING and UPDATING do not prove that their version is invocable."""
        service, results = _run(
            _mock(
                {AGENT_A_ID: SHARED_VERSION_ARN, AGENT_B_ID: SHARED_VERSION_ARN},
                alias_status=alias_status,
            )
        )

        for agent in service.all_agents.values():
            assert agent.versions_listed is False
            assert agent.version_role_arns == {}

        assert len(results) == 2
        assert {report.status for report in results} == {"MANUAL"}
        for report in results:
            assert "deployed versions of" in report.status_extended

    @pytest.mark.parametrize("alias_status", ["CREATING", "UPDATING"])
    @mock_aws
    def test_shared_draft_role_fails_despite_in_flight_alias(self, alias_status):
        """Definite draft sharing outranks an incomplete alias inventory."""
        service, results = _run(
            _mock(
                {AGENT_A_ID: DEDICATED_VERSION_ARN, AGENT_B_ID: DEDICATED_VERSION_ARN},
                alias_status=alias_status,
                draft_roles={AGENT_A_ID: DRAFT_A_ARN, AGENT_B_ID: DRAFT_A_ARN},
            )
        )

        assert all(
            agent.versions_listed is False for agent in service.all_agents.values()
        )
        assert {report.status for report in results} == {"FAIL"}
        assert all(DRAFT_A_ARN in report.status_extended for report in results)

    @mock_aws
    def test_prepared_accepting_alias_shares_its_version_role(self):
        """A PREPARED alias accepting invocations is active."""
        service, results = _run(
            _mock(
                {AGENT_A_ID: SHARED_VERSION_ARN, AGENT_B_ID: SHARED_VERSION_ARN},
                alias_status="PREPARED",
                alias_invocation_state="ACCEPT_INVOCATIONS",
            )
        )

        for agent in service.all_agents.values():
            assert agent.versions_listed is True
            assert agent.version_role_arns == {"3": SHARED_VERSION_ARN}

        assert {report.status for report in results} == {"FAIL"}

    @mock_aws
    def test_prepared_alias_sharing_fails_despite_in_flight_alias(self):
        """Definite prepared-version sharing outranks incomplete inventory."""
        service, results = _run(
            _mock(
                {AGENT_A_ID: SHARED_VERSION_ARN, AGENT_B_ID: SHARED_VERSION_ARN},
                aliases=[
                    {
                        "agentAliasId": "alias-prepared",
                        "agentAliasName": "production",
                        "agentAliasStatus": "PREPARED",
                        "routingConfiguration": [{"agentVersion": "3"}],
                    },
                    {
                        "agentAliasId": "alias-updating",
                        "agentAliasName": "next",
                        "agentAliasStatus": "UPDATING",
                        "routingConfiguration": [{"agentVersion": "4"}],
                    },
                ],
            )
        )

        for agent in service.all_agents.values():
            assert agent.versions_listed is False
            assert agent.version_role_arns == {"3": SHARED_VERSION_ARN}

        assert {report.status for report in results} == {"FAIL"}
        assert all("through deployed version 3" in r.status_extended for r in results)

    @mock_aws
    def test_absent_invocation_state_still_shares_its_version_role(self):
        """aliasInvocationState is optional; absent means never set to reject.

        Reading absence as "not accepting" would report every alias that was
        never explicitly enabled as dead, and a genuinely shared role as PASS.
        """
        service, results = _run(
            _mock(
                {AGENT_A_ID: SHARED_VERSION_ARN, AGENT_B_ID: SHARED_VERSION_ARN},
                alias_invocation_state=None,
            )
        )

        for agent in service.all_agents.values():
            assert agent.version_role_arns == {"3": SHARED_VERSION_ARN}

        assert {report.status for report in results} == {"FAIL"}

    @mock_aws
    def test_rejecting_alias_does_not_mask_a_shared_draft_role(self):
        """The predicate must gate ROUTING only, never the draft.

        The draft role comes from GetAgent, not from an alias, so an unreachable
        alias has no bearing on it. Without this, a predicate applied one level
        too high would silence a genuinely shared draft role.
        """
        service, results = _run(
            _mock(
                {AGENT_A_ID: DEDICATED_VERSION_ARN, AGENT_B_ID: DEDICATED_VERSION_ARN},
                alias_invocation_state="REJECT_INVOCATIONS",
            )
        )
        # No routed version survives the predicate...
        for agent in service.all_agents.values():
            assert agent.version_role_arns == {}
        # ...so make both DRAFTS share one role and re-run the verdict.
        for agent in service.all_agents.values():
            agent.role_arn = DRAFT_A_ARN

        check_name = "bedrock_agent_role_not_shared_across_agents"
        with mock.patch(
            f"prowler.providers.aws.services.bedrock.{check_name}.{check_name}"
            ".bedrock_agent_client",
            new=service,
        ):
            module = __import__(
                f"prowler.providers.aws.services.bedrock.{check_name}.{check_name}",
                fromlist=[check_name],
            )
            results = getattr(module, check_name)().execute()

        assert len(results) == 2
        assert {report.status for report in results} == {"FAIL"}
        for report in results:
            assert DRAFT_A_ARN in report.status_extended
            # The sharing is on the draft, so no version is named.
            assert "through deployed version" not in report.status_extended
