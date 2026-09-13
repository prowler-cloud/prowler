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

FLOW_ID = "ABCDEFGHIJ"
FLOW_NAME = "test-flow"
FLOW_ARN = f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:flow/{FLOW_ID}"
GUARDRAIL_ID = "test-guardrail-id"

# Operations the BedrockAgent constructor calls that these tests do not exercise.
_UNUSED_OPERATIONS = (
    "ListAgents",
    "GetAgent",
    "ListAgentAliases",
    "GetAgentVersion",
    "ListPrompts",
    "GetPrompt",
    "ListTagsForResource",
    "ListKnowledgeBases",
    "ListDataSources",
    "GetDataSource",
)


def _prompt_node(name, guardrail_id=None):
    configuration = {"prompt": {}}
    if guardrail_id is not None:
        configuration["prompt"]["guardrailConfiguration"] = {
            "guardrailIdentifier": guardrail_id,
            "guardrailVersion": "DRAFT",
        }
    return {"name": name, "type": "Prompt", "configuration": configuration}


def _knowledge_base_node(name, *, model_id=None, guardrail_id=None):
    knowledge_base = {"knowledgeBaseId": "kb-id"}
    if model_id is not None:
        knowledge_base["modelId"] = model_id
    if guardrail_id is not None:
        knowledge_base["guardrailConfiguration"] = {
            "guardrailIdentifier": guardrail_id,
            "guardrailVersion": "DRAFT",
        }
    return {
        "name": name,
        "type": "KnowledgeBase",
        "configuration": {"knowledgeBase": knowledge_base},
    }


def _flow_mock(
    *,
    nodes=None,
    fail_list=None,
    fail_get=False,
    omit_definition=False,
    extra_summaries=None,
):
    """Build a _make_api_call replacement returning Bedrock Flow inventory."""

    def _mock(self, operation_name, kwarg):
        if operation_name in _UNUSED_OPERATIONS:
            return {}
        if operation_name == "ListFlows":
            if fail_list:
                raise ClientError(
                    {"Error": {"Code": fail_list, "Message": "denied"}},
                    operation_name,
                )
            summaries = [
                {
                    "id": FLOW_ID,
                    "name": FLOW_NAME,
                    "arn": FLOW_ARN,
                }
            ]
            if extra_summaries:
                summaries.extend(extra_summaries)
            return {"flowSummaries": summaries}
        if operation_name == "GetFlow":
            if fail_get:
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                    operation_name,
                )
            response = {
                "id": FLOW_ID,
                "name": FLOW_NAME,
                "arn": FLOW_ARN,
            }
            if not omit_definition:
                response["definition"] = {"nodes": nodes or []}
            return response
        return make_api_call(self, operation_name, kwarg)

    return _mock


def _mock_empty(self, operation_name, kwarg):
    """No flows at all."""
    if operation_name in _UNUSED_OPERATIONS:
        return {}
    if operation_name == "ListFlows":
        return {"flowSummaries": []}
    return make_api_call(self, operation_name, kwarg)


_mock_prompt_with_guardrail = _flow_mock(
    nodes=[_prompt_node("prompt-node", GUARDRAIL_ID)]
)
_mock_prompt_without_guardrail = _flow_mock(nodes=[_prompt_node("prompt-node")])
_mock_mixed_prompt_nodes = _flow_mock(
    nodes=[
        _prompt_node("guarded-prompt", GUARDRAIL_ID),
        _prompt_node("unguarded-prompt"),
    ]
)
_mock_kb_generate_without_guardrail = _flow_mock(
    nodes=[
        _knowledge_base_node(
            "kb-generate",
            model_id="amazon.titan-text-express-v1",
        )
    ]
)
_mock_kb_generate_with_guardrail = _flow_mock(
    nodes=[
        _knowledge_base_node(
            "kb-generate",
            model_id="amazon.titan-text-express-v1",
            guardrail_id=GUARDRAIL_ID,
        )
    ]
)
_mock_retrieve_only_kb = _flow_mock(nodes=[_knowledge_base_node("kb-retrieve-only")])
_mock_input_output_only = _flow_mock(
    nodes=[
        {"name": "input", "type": "Input", "configuration": {}},
        {"name": "output", "type": "Output", "configuration": {}},
    ]
)
_mock_unreadable = _flow_mock(nodes=[_prompt_node("prompt-node")], fail_get=True)
_mock_missing_definition = _flow_mock(omit_definition=True)
_mock_list_denied = _flow_mock(fail_list="AccessDeniedException")
_mock_unsupported_region = _flow_mock(fail_list="ValidationException")


def _mock_unrelated_resources(self, operation_name, kwarg):
    """Agents, prompts, and knowledge bases exist, but no flows do."""
    if operation_name == "ListAgents":
        return {
            "agentSummaries": [
                {"agentId": "agentid001", "agentName": "unrelated-agent"}
            ]
        }
    if operation_name == "ListPrompts":
        return {
            "promptSummaries": [
                {
                    "id": "prompt-1",
                    "name": "unrelated-prompt",
                    "arn": f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:prompt/prompt-1",
                }
            ]
        }
    if operation_name == "ListKnowledgeBases":
        return {
            "knowledgeBaseSummaries": [
                {"knowledgeBaseId": "kb-1", "name": "unrelated-kb"}
            ]
        }
    if operation_name == "ListFlows":
        return {"flowSummaries": []}
    if operation_name in _UNUSED_OPERATIONS:
        return {}
    return make_api_call(self, operation_name, kwarg)


class Test_bedrock_flow_guardrail_enabled:
    """Unit tests for the bedrock_flow_guardrail_enabled check."""

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
                "prowler.providers.aws.services.bedrock.bedrock_flow_guardrail_enabled.bedrock_flow_guardrail_enabled.bedrock_agent_client",
                new=BedrockAgent(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_flow_guardrail_enabled.bedrock_flow_guardrail_enabled import (
                bedrock_flow_guardrail_enabled,
            )

            return bedrock_flow_guardrail_enabled().execute()

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_empty)
    @mock_aws
    def test_no_resources(self):
        """No flows means no findings, not a spurious FAIL."""
        assert self._run() == []

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_unsupported_region
    )
    @mock_aws
    def test_region_not_supported(self):
        """A ValidationException from the region must not raise; it yields no findings."""
        assert self._run() == []

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_prompt_with_guardrail
    )
    @mock_aws
    def test_prompt_node_with_guardrail_passes(self):
        """A Prompt node with guardrailIdentifier is compliant."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == FLOW_ID
        assert result[0].resource_arn == FLOW_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
        assert (
            result[0].status_extended
            == f"Bedrock Flow {FLOW_NAME} applies a guardrail to all applicable prompt nodes in region {AWS_REGION_US_EAST_1}."
        )

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_prompt_without_guardrail
    )
    @mock_aws
    def test_prompt_node_without_guardrail_fails(self):
        """A Prompt node without a guardrail is a FAIL."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_id == FLOW_ID
        assert "unguarded-prompt" not in result[0].status_extended
        assert "prompt-node (Prompt)" in result[0].status_extended
        assert result[0].status_extended.endswith(".")

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_mixed_prompt_nodes
    )
    @mock_aws
    def test_mixed_prompt_nodes_fails(self):
        """One unguarded applicable node fails the whole flow."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "unguarded-prompt (Prompt)" in result[0].status_extended

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock_kb_generate_without_guardrail,
    )
    @mock_aws
    def test_generating_knowledge_base_without_guardrail_fails(self):
        """A KnowledgeBase node that generates responses must have a guardrail."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "kb-generate (KnowledgeBase)" in result[0].status_extended

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock_kb_generate_with_guardrail,
    )
    @mock_aws
    def test_generating_knowledge_base_with_guardrail_passes(self):
        """A generating KnowledgeBase node with a guardrail is compliant."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_retrieve_only_kb)
    @mock_aws
    def test_retrieve_only_knowledge_base_is_not_applicable(self):
        """Retrieve-only KnowledgeBase nodes cannot attach a guardrail."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            "no applicable prompt or knowledge base nodes" in result[0].status_extended
        )

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_input_output_only
    )
    @mock_aws
    def test_flow_without_applicable_nodes_passes(self):
        """Input/Output-only flows have no prompt path that requires a guardrail."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            "no applicable prompt or knowledge base nodes" in result[0].status_extended
        )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_unreadable)
    @mock_aws
    def test_definition_unreadable_is_manual_not_pass(self):
        """A failed GetFlow must not be reported as compliant."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == FLOW_ID
        assert "could not be retrieved" in result[0].status_extended
        assert result[0].status_extended.endswith(".")

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_missing_definition
    )
    @mock_aws
    def test_missing_definition_is_manual_not_pass(self):
        """GetFlow without a definition is indeterminate, not an empty graph."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be retrieved" in result[0].status_extended

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_list_denied)
    @mock_aws
    def test_list_denied_is_manual_not_silence(self):
        """A denied ListFlows must report MANUAL, not vanish.

        Without a region-level report the region is indistinguishable from one
        that genuinely holds no flows.
        """
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].resource_id == "flow/unknown"
        assert (
            result[0].resource_arn
            == f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:flow/unknown"
        )
        assert "could not be listed" in result[0].status_extended
        assert "AccessDeniedException" in result[0].status_extended
        assert result[0].status_extended.endswith(".")

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_unrelated_resources
    )
    @mock_aws
    def test_unrelated_resources_are_not_reported(self):
        """Agents, prompts, and knowledge bases must not produce flow findings."""
        assert self._run() == []
