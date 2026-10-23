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
    """Serve one fully configured guardrail, and defer any other operation to botocore.

    The sensitiveInformationPolicy carries one PII entity and one regex, both with an action and
    neither with outputAction or outputEnabled, which is the shape GetGuardrail returns when the
    per-path settings were never configured.
    """
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
            "sensitiveInformationPolicy": {
                "piiEntities": [{"type": "EMAIL", "action": "ANONYMIZE"}],
                "regexes": [
                    {
                        "name": "account-id",
                        "pattern": "[0-9]{12}",
                        "action": "BLOCK",
                    }
                ],
            },
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


def mock_make_api_call_guardrail_regex_output_path(self, operation_name, kwarg):
    """A guardrail whose REGEX carries explicit per-path settings.

    The shared fixture omits outputAction and outputEnabled on both arms, so an assertion that they
    are all None passes whether or not the regex arm reads them -- it cannot discriminate. This
    fixture blocks on input and leaks on output, which is the shape that separates the two.
    """
    if operation_name == "GetGuardrail":
        return {
            "guardrailArn": GUARDRAIL_ARN,
            "guardrailId": "test-id",
            "name": "test",
            "status": "READY",
            "sensitiveInformationPolicy": {
                "regexes": [
                    {
                        "name": "internal-token",
                        "pattern": "tok-[0-9]+",
                        "action": "BLOCK",
                        "outputAction": "NONE",
                        "outputEnabled": True,
                    }
                ]
            },
            "blockedInputMessaging": "no",
            "blockedOutputsMessaging": "no",
        }
    return mock_make_api_call(self, operation_name, kwarg)


def mock_make_api_call_get_guardrail_denied(self, operation_name, kwarg):
    """List the guardrail successfully but deny GetGuardrail.

    Reproduces the partial-permission state a caller holding bedrock:ListGuardrails without
    bedrock:GetGuardrail sees: the resource is known to exist, its configuration is not.
    """
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
        raise botocore.exceptions.ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "not authorized to perform: bedrock:GetGuardrail",
                }
            },
            "GetGuardrail",
        )
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

    @mock_aws
    def test_get_model_invocation_logging_delivery_flags(self):
        """The delivery flags must be carried through, not inferred from the destination.

        A configuration can name a log group while excluding the request and response bodies.
        Asserting only `enabled` reports content capture that is switched off.
        """
        aws_provider = set_mocked_aws_provider(audited_regions=[AWS_REGION_EU_WEST_1])
        bedrock_client_eu_west_1 = client("bedrock", region_name="eu-west-1")
        bedrock_client_eu_west_1.put_model_invocation_logging_configuration(
            loggingConfig={
                "cloudWatchConfig": {"logGroupName": "Test", "roleArn": "testrole"},
                "textDataDeliveryEnabled": False,
                "imageDataDeliveryEnabled": False,
                "embeddingDataDeliveryEnabled": True,
                "videoDataDeliveryEnabled": False,
            }
        )
        bedrock = Bedrock(aws_provider)
        config = bedrock.logging_configurations[AWS_REGION_EU_WEST_1]
        assert config.enabled
        assert config.text_data_delivery_enabled is False
        assert config.image_data_delivery_enabled is False
        assert config.embedding_data_delivery_enabled is True
        # The fourth flag was the one of four asserted nowhere, so its read could be mis-keyed or
        # dropped with the suite green. False rather than True on purpose: it differs from the
        # embedding flag beside it, so a swap between the two is caught as well as a read that
        # returns None.
        assert config.video_data_delivery_enabled is False

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
        """A guardrail read without error must record the filters found and no error.

        detail_retrieved True with detail_error None is the state that entitles a check to make a
        claim about the filters; it is asserted here so the clean read is distinguishable from the
        denied read rather than only inferable from it.
        """
        aws_provider = set_mocked_aws_provider(audited_regions=[AWS_REGION_US_EAST_1])
        bedrock = Bedrock(aws_provider)
        assert bedrock.guardrails[GUARDRAIL_ARN].sensitive_information_filter
        assert bedrock.guardrails[GUARDRAIL_ARN].prompt_attack_filter_strength == "HIGH"
        assert bedrock.guardrails[GUARDRAIL_ARN].detail_retrieved is True
        assert bedrock.guardrails[GUARDRAIL_ARN].detail_error is None

    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_get_guardrail_sensitive_information_entries(self):
        """Every PII entity and regex must be carried through with its per-path action.

        The presence of a sensitive information policy says nothing about whether a match is
        acted on: an entry whose action is NONE detects the value and still returns it.
        """
        aws_provider = set_mocked_aws_provider(audited_regions=[AWS_REGION_US_EAST_1])
        bedrock = Bedrock(aws_provider)
        entries = bedrock.guardrails[GUARDRAIL_ARN].sensitive_information_entries
        assert [entry.name for entry in entries] == [
            "PII entity EMAIL",
            "regex account-id",
        ]
        assert entries[0].action == "ANONYMIZE"
        assert entries[1].action == "BLOCK"
        # The API omits the per-path settings unless they were configured explicitly.
        assert all(entry.output_action is None for entry in entries)
        assert all(entry.output_enabled is None for entry in entries)

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_guardrail_regex_output_path,
    )
    @mock_aws
    def test_get_guardrail_regex_carries_its_per_path_settings(self):
        """A regex's outputAction and outputEnabled must be read, not only a PII entity's.

        Mis-keying either read on the regex arm left all 202 bedrock tests green while a guardrail
        that blocks on input and leaks on output flipped FAIL -> PASS in the check above -- its
        central claim, output-path enforcement, reversed with nothing failing. The PII arm was
        already covered; only the regex arm was not, and the existing assertion could not tell,
        because the shared fixture omits these fields on both arms so `all(... is None)` holds
        either way.
        """
        aws_provider = set_mocked_aws_provider(audited_regions=[AWS_REGION_US_EAST_1])
        bedrock = Bedrock(aws_provider)
        entries = bedrock.guardrails[GUARDRAIL_ARN].sensitive_information_entries
        assert [entry.name for entry in entries] == ["regex internal-token"]
        assert entries[0].action == "BLOCK"
        assert entries[0].output_action == "NONE"
        assert entries[0].output_enabled is True

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_get_guardrail_denied,
    )
    @mock_aws
    def test_get_guardrail_error_records_unretrieved_detail(self):
        """A guardrail whose detail was never read must be distinguishable from a clean read."""
        aws_provider = set_mocked_aws_provider(audited_regions=[AWS_REGION_US_EAST_1])
        bedrock = Bedrock(aws_provider)
        guardrail = bedrock.guardrails[GUARDRAIL_ARN]
        assert guardrail.detail_retrieved is False
        assert guardrail.detail_error == "AccessDeniedException"
        assert guardrail.sensitive_information_entries == []

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
