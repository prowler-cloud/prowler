from unittest import mock

import botocore
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
