from unittest import mock
from unittest.mock import MagicMock

import botocore
import pytest
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.bedrock.bedrock_service import Bedrock, BedrockAgent
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call

GUARDRAIL_ARN = (
    f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:guardrail/test-id"
)


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListGuardrails":
        return {
            "guardrails": [
                {
                    "id": "test-id",
                    "arn": GUARDRAIL_ARN,
                    "status": "READY",
                    "name": "test",
                }
            ]
        }
    elif operation_name == "GetGuardrail":
        return {
            "name": "test",
            "guardrailId": "test-id",
            "guardrailArn": GUARDRAIL_ARN,
            "status": "READY",
            "contentPolicy": {
                "filters": [
                    {
                        "type": "PROMPT_ATTACK",
                        "inputStrength": "HIGH",
                        "outputStrength": "NONE",
                    },
                ]
            },
            "sensitiveInformationPolicy": True,
            "blockedInputMessaging": "Sorry, the model cannot answer this question.",
            "blockedOutputsMessaging": "Sorry, the model cannot answer this question.",
        }
    elif operation_name == "ListTagsForResource":
        return {
            "tags": [
                {"Key": "Name", "Value": "test"},
            ]
        }
    return make_api_call(self, operation_name, kwarg)


class Test_Bedrock_Service:
    @mock_aws
    def test_service(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        bedrock = Bedrock(aws_provider)
        assert bedrock.service == "bedrock"

    @mock_aws
    def test_client(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        bedrock = Bedrock(aws_provider)
        for regional_client in bedrock.regional_clients.values():
            assert regional_client.__class__.__name__ == "Bedrock"

    @mock_aws
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        bedrock = Bedrock(aws_provider)
        assert bedrock.session.__class__.__name__ == "Session"

    @mock_aws
    def test_audited_account(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        bedrock = Bedrock(aws_provider)
        assert bedrock.audited_account == AWS_ACCOUNT_NUMBER

    @mock_aws
    def test_get_model_invocation_logging_configuration(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        bedrock_client_eu_west_1 = client("bedrock", region_name="eu-west-1")
        logging_config = {
            "cloudWatchConfig": {
                "logGroupName": "Test",
                "roleArn": "testrole",
                "largeDataDeliveryS3Config": {
                    "bucketName": "testbucket",
                },
            },
            "s3Config": {
                "bucketName": "testconfigbucket",
            },
        }
        bedrock_client_eu_west_1.put_model_invocation_logging_configuration(
            loggingConfig=logging_config
        )
        bedrock = Bedrock(aws_provider)
        assert len(bedrock.logging_configurations) == 2
        assert bedrock.logging_configurations[AWS_REGION_EU_WEST_1].enabled
        assert (
            bedrock.logging_configurations[AWS_REGION_EU_WEST_1].cloudwatch_log_group
            == "Test"
        )
        assert (
            bedrock.logging_configurations[AWS_REGION_EU_WEST_1].s3_bucket
            == "testconfigbucket"
        )
        assert not bedrock.logging_configurations[AWS_REGION_US_EAST_1].enabled

    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_list_guardrails(self):
        aws_provider = set_mocked_aws_provider(audited_regions=[AWS_REGION_US_EAST_1])
        bedrock = Bedrock(aws_provider)
        assert len(bedrock.guardrails) == 1
        assert GUARDRAIL_ARN in bedrock.guardrails
        assert bedrock.guardrails[GUARDRAIL_ARN].id == "test-id"
        assert bedrock.guardrails[GUARDRAIL_ARN].name == "test"
        assert bedrock.guardrails[GUARDRAIL_ARN].region == AWS_REGION_US_EAST_1

    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_get_guardrail(self):
        aws_provider = set_mocked_aws_provider(audited_regions=[AWS_REGION_US_EAST_1])
        bedrock = Bedrock(aws_provider)
        assert bedrock.guardrails[GUARDRAIL_ARN].sensitive_information_filter
        assert bedrock.guardrails[GUARDRAIL_ARN].prompt_attack_filter_strength == "HIGH"

    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_list_tags_for_resource(self):
        aws_provider = set_mocked_aws_provider(audited_regions=[AWS_REGION_US_EAST_1])
        bedrock = Bedrock(aws_provider)
        assert bedrock.guardrails[GUARDRAIL_ARN].tags == [
            {"Key": "Name", "Value": "test"}
        ]


class Test_Bedrock_Agent_Service:
    @mock_aws
    def test_service(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        bedrock_agent = BedrockAgent(aws_provider)
        assert bedrock_agent.service == "bedrock-agent"

    @mock_aws
    def test_client(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        bedrock_agent = BedrockAgent(aws_provider)
        for regional_client in bedrock_agent.regional_clients.values():
            assert regional_client.__class__.__name__ == "AgentsforBedrock"

    @mock_aws
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        bedrock_agent = BedrockAgent(aws_provider)
        assert bedrock_agent.session.__class__.__name__ == "Session"

    @mock_aws
    def test_audited_account(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        bedrock_agent = BedrockAgent(aws_provider)
        assert bedrock_agent.audited_account == AWS_ACCOUNT_NUMBER

    @mock_aws
    def test_list_agents(self):
        bedrock_agent_client = client("bedrock-agent", region_name=AWS_REGION_US_EAST_1)
        agent = bedrock_agent_client.create_agent(
            agentName="agent_name",
            agentResourceRoleArn="test-agent-arn",
            tags={
                "Key": "test-tag-key",
            },
        )["agent"]
        agent_id = agent["agentId"]
        agent_arn = agent["agentArn"]
        agent_name = agent["agentName"]
        aws_provider = set_mocked_aws_provider(audited_regions=[AWS_REGION_US_EAST_1])
        bedrock_agent = BedrockAgent(aws_provider)
        assert len(bedrock_agent.agents) == 1
        assert bedrock_agent.agents[agent_arn].id == agent_id
        assert bedrock_agent.agents[agent_arn].name == agent_name
        assert bedrock_agent.agents[agent_arn].region == AWS_REGION_US_EAST_1
        assert bedrock_agent.agents[agent_arn].guardrail_id is None
        assert bedrock_agent.agents[agent_arn].tags == [
            {
                "Key": "test-tag-key",
            }
        ]


class TestBedrockPagination:
    """Test suite for Bedrock Guardrail pagination logic."""

    def test_list_guardrails_pagination(self):
        """Test that list_guardrails iterates through all pages."""
        # Mock the audit_info
        audit_info = MagicMock()
        audit_info.audited_partition = "aws"
        audit_info.audited_account = "123456789012"
        audit_info.audit_resources = None

        # Mock the regional client
        regional_client = MagicMock()
        regional_client.region = "us-east-1"

        # Mock paginator
        paginator = MagicMock()
        page1 = {
            "guardrails": [
                {
                    "id": "g-1",
                    "name": "guardrail-1",
                    "arn": "arn:aws:bedrock:us-east-1:123456789012:guardrail/g-1",
                }
            ]
        }
        page2 = {
            "guardrails": [
                {
                    "id": "g-2",
                    "name": "guardrail-2",
                    "arn": "arn:aws:bedrock:us-east-1:123456789012:guardrail/g-2",
                }
            ]
        }
        paginator.paginate.return_value = [page1, page2]
        regional_client.get_paginator.return_value = paginator

        # Initialize service and inject mock client
        bedrock_service = Bedrock(audit_info)
        bedrock_service.regional_clients = {"us-east-1": regional_client}
        bedrock_service.guardrails = {}  # Clear any init side effects

        # Run the method under test
        bedrock_service._list_guardrails(regional_client)

        # Assertions
        assert len(bedrock_service.guardrails) == 2
        assert (
            "arn:aws:bedrock:us-east-1:123456789012:guardrail/g-1"
            in bedrock_service.guardrails
        )
        assert (
            "arn:aws:bedrock:us-east-1:123456789012:guardrail/g-2"
            in bedrock_service.guardrails
        )

        # Verify paginator was used
        regional_client.get_paginator.assert_called_once_with("list_guardrails")
        paginator.paginate.assert_called_once()


class TestBedrockAgentPagination:
    """Test suite for Bedrock Agent pagination logic."""

    @pytest.mark.parametrize("partition", ["aws", "aws-us-gov", "aws-cn"])
    def test_list_agents_pagination(self, partition):
        """Test that list_agents iterates through all pages, in every partition.

        The ARN is built from the audited partition, so GovCloud and China must
        produce aws-us-gov/aws-cn ARNs. A hardcoded `arn:aws:` here yielded an ARN
        that does not exist in those partitions, and exact --resource-arn matching
        against it could never succeed.
        """
        # Mock the audit_info. AWSService reads the partition off provider.identity,
        # so setting audited_partition alone leaves a MagicMock in the ARN.
        audit_info = MagicMock()
        audit_info.identity.partition = partition
        audit_info.audited_partition = partition
        audit_info.audited_account = "123456789012"
        audit_info.audit_resources = None

        # Mock the regional client
        regional_client = MagicMock()
        regional_client.region = "us-east-1"

        # Mock paginator
        paginator = MagicMock()
        page1 = {
            "agentSummaries": [
                {
                    "agentId": "agent-1",
                    "agentName": "agent-name-1",
                    "agentStatus": "PREPARED",
                }
            ]
        }
        page2 = {
            "agentSummaries": [
                {
                    "agentId": "agent-2",
                    "agentName": "agent-name-2",
                    "agentStatus": "PREPARED",
                }
            ]
        }
        paginator.paginate.return_value = [page1, page2]
        regional_client.get_paginator.return_value = paginator

        # Initialize service and inject mock client
        bedrock_agent_service = BedrockAgent(audit_info)
        bedrock_agent_service.regional_clients = {"us-east-1": regional_client}
        bedrock_agent_service.agents = {}  # Clear init side effects
        bedrock_agent_service.all_agents = {}
        bedrock_agent_service.audited_account = "123456789012"

        # Run method
        bedrock_agent_service._list_agents(regional_client)

        # Assertions
        assert len(bedrock_agent_service.agents) == 2
        for agent_id in ("agent-1", "agent-2"):
            expected_arn = (
                f"arn:{partition}:bedrock:us-east-1:123456789012:agent/{agent_id}"
            )
            assert expected_arn in bedrock_agent_service.agents
            # With no --resource-arn, the complete inventory and the reported set
            # hold the very same objects.
            assert bedrock_agent_service.all_agents[expected_arn] is (
                bedrock_agent_service.agents[expected_arn]
            )

        # Verify paginator was used
        regional_client.get_paginator.assert_called_once_with("list_agents")
        paginator.paginate.assert_called_once()


class TestBedrockPromptPagination:
    """Test suite for Bedrock Prompt pagination logic."""

    def test_list_prompts_pagination(self):
        """Test that list_prompts iterates through all pages."""
        # Mock the audit_info
        audit_info = MagicMock()
        audit_info.audited_partition = "aws"
        audit_info.audited_account = "123456789012"
        audit_info.audit_resources = None

        # Mock the regional client
        regional_client = MagicMock()
        regional_client.region = "us-east-1"

        # Mock paginator
        paginator = MagicMock()
        page1 = {
            "promptSummaries": [
                {
                    "id": "prompt-1",
                    "name": "prompt-name-1",
                    "arn": "arn:aws:bedrock:us-east-1:123456789012:prompt/prompt-1",
                }
            ]
        }
        page2 = {
            "promptSummaries": [
                {
                    "id": "prompt-2",
                    "name": "prompt-name-2",
                    "arn": "arn:aws:bedrock:us-east-1:123456789012:prompt/prompt-2",
                }
            ]
        }
        paginator.paginate.return_value = [page1, page2]
        regional_client.get_paginator.return_value = paginator

        # Initialize service and inject mock client
        bedrock_agent_service = BedrockAgent(audit_info)
        bedrock_agent_service.regional_clients = {"us-east-1": regional_client}
        bedrock_agent_service.prompts = {}  # Clear init side effects
        bedrock_agent_service.prompt_scanned_regions = set()

        # Run method
        bedrock_agent_service._list_prompts(regional_client)

        # Assertions
        assert len(bedrock_agent_service.prompts) == 2
        assert (
            "arn:aws:bedrock:us-east-1:123456789012:prompt/prompt-1"
            in bedrock_agent_service.prompts
        )
        assert (
            "arn:aws:bedrock:us-east-1:123456789012:prompt/prompt-2"
            in bedrock_agent_service.prompts
        )
        assert "us-east-1" in bedrock_agent_service.prompt_scanned_regions

        # Verify paginator was used
        regional_client.get_paginator.assert_called_once_with("list_prompts")
        paginator.paginate.assert_called_once()

    def test_list_prompts_filters_audit_resources(self):
        """Prompt collection must honor audit_resources when resource ARNs are scoped."""
        audit_info = MagicMock()
        audit_info.audited_partition = "aws"
        audit_info.audited_account = "123456789012"
        audit_info.audit_resources = [
            "arn:aws:bedrock:us-east-1:123456789012:prompt/prompt-1"
        ]

        regional_client = MagicMock()
        regional_client.region = "us-east-1"

        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "promptSummaries": [
                    {
                        "id": "prompt-1",
                        "name": "prompt-name-1",
                        "arn": "arn:aws:bedrock:us-east-1:123456789012:prompt/prompt-1",
                    },
                    {
                        "id": "prompt-2",
                        "name": "prompt-name-2",
                        "arn": "arn:aws:bedrock:us-east-1:123456789012:prompt/prompt-2",
                    },
                ]
            }
        ]
        regional_client.get_paginator.return_value = paginator

        bedrock_agent_service = BedrockAgent(audit_info)
        bedrock_agent_service.regional_clients = {"us-east-1": regional_client}
        bedrock_agent_service.prompts = {}
        bedrock_agent_service.prompt_scanned_regions = set()

        bedrock_agent_service._list_prompts(regional_client)

        assert len(bedrock_agent_service.prompts) == 1
        assert (
            "arn:aws:bedrock:us-east-1:123456789012:prompt/prompt-1"
            in bedrock_agent_service.prompts
        )
        assert (
            "arn:aws:bedrock:us-east-1:123456789012:prompt/prompt-2"
            not in bedrock_agent_service.prompts
        )
        assert "us-east-1" in bedrock_agent_service.prompt_scanned_regions

    def test_list_prompts_error_does_not_mark_region_scanned(self):
        """If ListPrompts raises, the region must not be added to prompt_scanned_regions."""
        audit_info = MagicMock()
        audit_info.audited_partition = "aws"
        audit_info.audited_account = "123456789012"
        audit_info.audit_resources = None

        regional_client = MagicMock()
        regional_client.region = "us-east-1"

        paginator = MagicMock()
        paginator.paginate.side_effect = Exception("ListPrompts failed")
        regional_client.get_paginator.return_value = paginator

        bedrock_agent_service = BedrockAgent(audit_info)
        bedrock_agent_service.regional_clients = {"us-east-1": regional_client}
        bedrock_agent_service.prompts = {}
        bedrock_agent_service.prompt_scanned_regions = set()

        bedrock_agent_service._list_prompts(regional_client)

        assert bedrock_agent_service.prompts == {}
        assert bedrock_agent_service.prompt_scanned_regions == set()


class TestBedrockFlowCollection:
    """Test suite for Bedrock Flow inventory used by flow guardrail checks."""

    FLOW_ID = "ABCDEFGHIJ"
    FLOW_ARN = f"arn:aws:bedrock:us-east-1:123456789012:flow/{FLOW_ID}"

    def _service(self, regional_client):
        audit_info = MagicMock()
        audit_info.audited_partition = "aws"
        audit_info.audited_account = "123456789012"
        audit_info.audit_resources = None

        bedrock_agent_service = BedrockAgent(audit_info)
        bedrock_agent_service.regional_clients = {"us-east-1": regional_client}
        bedrock_agent_service.flows = {}
        bedrock_agent_service.flows_scan_errors = {}
        bedrock_agent_service.audited_account = "123456789012"
        bedrock_agent_service.audited_partition = "aws"
        return bedrock_agent_service

    def test_list_flows_pagination(self):
        """Test that list_flows iterates through all pages."""
        regional_client = MagicMock()
        regional_client.region = "us-east-1"

        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "flowSummaries": [
                    {
                        "id": "flowid0001",
                        "name": "flow-1",
                        "arn": "arn:aws:bedrock:us-east-1:123456789012:flow/flowid0001",
                    }
                ]
            },
            {
                "flowSummaries": [
                    {
                        "id": "flowid0002",
                        "name": "flow-2",
                        "arn": "arn:aws:bedrock:us-east-1:123456789012:flow/flowid0002",
                    }
                ]
            },
        ]
        regional_client.get_paginator.return_value = paginator

        bedrock_agent_service = self._service(regional_client)
        bedrock_agent_service._list_flows(regional_client)

        assert len(bedrock_agent_service.flows) == 2
        assert (
            "arn:aws:bedrock:us-east-1:123456789012:flow/flowid0001"
            in bedrock_agent_service.flows
        )
        assert (
            "arn:aws:bedrock:us-east-1:123456789012:flow/flowid0002"
            in bedrock_agent_service.flows
        )
        regional_client.get_paginator.assert_called_once_with("list_flows")
        paginator.paginate.assert_called_once()

    def test_list_flows_filters_audit_resources(self):
        """Flow collection must honor audit_resources when resource ARNs are scoped."""
        regional_client = MagicMock()
        regional_client.region = "us-east-1"

        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "flowSummaries": [
                    {
                        "id": "flowid0001",
                        "name": "flow-1",
                        "arn": "arn:aws:bedrock:us-east-1:123456789012:flow/flowid0001",
                    },
                    {
                        "id": "flowid0002",
                        "name": "flow-2",
                        "arn": "arn:aws:bedrock:us-east-1:123456789012:flow/flowid0002",
                    },
                ]
            }
        ]
        regional_client.get_paginator.return_value = paginator

        bedrock_agent_service = self._service(regional_client)
        bedrock_agent_service.audit_resources = [
            "arn:aws:bedrock:us-east-1:123456789012:flow/flowid0001"
        ]
        bedrock_agent_service._list_flows(regional_client)

        assert len(bedrock_agent_service.flows) == 1
        assert (
            "arn:aws:bedrock:us-east-1:123456789012:flow/flowid0001"
            in bedrock_agent_service.flows
        )
        assert (
            "arn:aws:bedrock:us-east-1:123456789012:flow/flowid0002"
            not in bedrock_agent_service.flows
        )

    def test_list_flows_access_denied_records_scan_error(self):
        """AccessDenied on ListFlows must be recorded, not treated as an empty region."""
        from botocore.exceptions import ClientError

        regional_client = MagicMock()
        regional_client.region = "us-east-1"
        paginator = MagicMock()
        paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "ListFlows",
        )
        regional_client.get_paginator.return_value = paginator

        bedrock_agent_service = self._service(regional_client)
        bedrock_agent_service._list_flows(regional_client)

        assert bedrock_agent_service.flows == {}
        assert (
            bedrock_agent_service.flows_scan_errors["us-east-1"]
            == "AccessDeniedException"
        )

    def test_list_flows_validation_exception_is_empty_not_error(self):
        """ValidationException means Flows are unavailable in the region, not unknown."""
        from botocore.exceptions import ClientError

        regional_client = MagicMock()
        regional_client.region = "us-east-1"
        paginator = MagicMock()
        paginator.paginate.side_effect = ClientError(
            {
                "Error": {
                    "Code": "ValidationException",
                    "Message": "Bedrock Flows is not supported in this region.",
                }
            },
            "ListFlows",
        )
        regional_client.get_paginator.return_value = paginator

        bedrock_agent_service = self._service(regional_client)
        bedrock_agent_service._list_flows(regional_client)

        assert bedrock_agent_service.flows == {}
        assert bedrock_agent_service.flows_scan_errors == {}

    def test_get_flow_stores_prompt_and_knowledge_base_guardrails(self):
        """GetFlow must retain node-level guardrail identifiers for applicable nodes."""
        regional_client = MagicMock()
        regional_client.region = "us-east-1"
        regional_client.get_flow.return_value = {
            "id": self.FLOW_ID,
            "name": "secured-flow",
            "arn": self.FLOW_ARN,
            "definition": {
                "nodes": [
                    {
                        "name": "prompt-node",
                        "type": "Prompt",
                        "configuration": {
                            "prompt": {
                                "guardrailConfiguration": {
                                    "guardrailIdentifier": "gr-prompt",
                                    "guardrailVersion": "DRAFT",
                                }
                            }
                        },
                    },
                    {
                        "name": "kb-generate",
                        "type": "KnowledgeBase",
                        "configuration": {
                            "knowledgeBase": {
                                "knowledgeBaseId": "kb-1",
                                "modelId": "amazon.titan-text-express-v1",
                                "guardrailConfiguration": {
                                    "guardrailIdentifier": "gr-kb",
                                },
                            }
                        },
                    },
                    {
                        "name": "kb-retrieve-only",
                        "type": "KnowledgeBase",
                        "configuration": {
                            "knowledgeBase": {
                                "knowledgeBaseId": "kb-2",
                            }
                        },
                    },
                    {"name": "input", "type": "Input", "configuration": {}},
                ]
            },
        }

        from prowler.providers.aws.services.bedrock.bedrock_service import Flow

        flow = Flow(
            id=self.FLOW_ID,
            name="secured-flow",
            arn=self.FLOW_ARN,
            region="us-east-1",
        )
        bedrock_agent_service = self._service(regional_client)
        bedrock_agent_service.regional_clients = {"us-east-1": regional_client}
        bedrock_agent_service._get_flow(flow)

        assert flow.definition_available is True
        applicable = [node for node in flow.nodes if node.applicable]
        assert {node.name for node in applicable} == {"prompt-node", "kb-generate"}
        by_name = {node.name: node for node in applicable}
        assert by_name["prompt-node"].guardrail_id == "gr-prompt"
        assert by_name["kb-generate"].guardrail_id == "gr-kb"

    def test_get_flow_error_leaves_definition_unavailable(self):
        """A failed GetFlow must not be treated as an empty (compliant) definition."""
        from botocore.exceptions import ClientError

        regional_client = MagicMock()
        regional_client.region = "us-east-1"
        regional_client.get_flow.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "GetFlow",
        )

        from prowler.providers.aws.services.bedrock.bedrock_service import Flow

        flow = Flow(
            id=self.FLOW_ID,
            name="unreadable-flow",
            arn=self.FLOW_ARN,
            region="us-east-1",
        )
        bedrock_agent_service = self._service(regional_client)
        bedrock_agent_service.regional_clients = {"us-east-1": regional_client}
        bedrock_agent_service._get_flow(flow)

        assert flow.definition_available is False
        assert flow.nodes == []
