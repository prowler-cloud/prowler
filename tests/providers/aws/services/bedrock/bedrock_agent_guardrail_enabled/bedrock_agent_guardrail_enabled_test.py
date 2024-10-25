from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call_no_guardrail(self, operation_name, kwarg):
    if operation_name == "ListAgents":
        return {
            "agentSummaries": [
                {
                    "agentId": "test-agent-id",
                    "agentName": "test-agent-name",
                    "guardrailConfiguration": {
                        "guardrailIdentifier": "test-guardrail-id",
                        "guardrailVersion": "test-guardrail-version",
                    },
                },
            ],
        }
    return make_api_call(self, operation_name, kwarg)


class Test_bedrock_agent_guardrail_enabled:
    @mock_aws
    def test_no_agents(self):
        from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_agent_guardrail_enabled.bedrock_agent_guardrail_enabled.bedrock_agent_client",
            new=BedrockAgent(aws_provider),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_agent_guardrail_enabled.bedrock_agent_guardrail_enabled import (
                bedrock_agent_guardrail_enabled,
            )

            check = bedrock_agent_guardrail_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_agent_without_guardrail(self):
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
        from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_agent_guardrail_enabled.bedrock_agent_guardrail_enabled.bedrock_agent_client",
            new=BedrockAgent(aws_provider),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_agent_guardrail_enabled.bedrock_agent_guardrail_enabled import (
                bedrock_agent_guardrail_enabled,
            )

            check = bedrock_agent_guardrail_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Bedrock Agent {agent_name} is not using any guardrail to protect agent sessions."
            )
            assert result[0].resource_id == agent_id
            assert result[0].resource_arn == agent_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{"Key": "test-tag-key"}]

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_no_guardrail
    )
    @mock_aws
    def test_agent_with_guardrail(self):
        from prowler.providers.aws.services.bedrock.bedrock_service import BedrockAgent

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.bedrock.bedrock_agent_guardrail_enabled.bedrock_agent_guardrail_enabled.bedrock_agent_client",
            new=BedrockAgent(aws_provider),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_agent_guardrail_enabled.bedrock_agent_guardrail_enabled import (
                bedrock_agent_guardrail_enabled,
            )

            check = bedrock_agent_guardrail_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Bedrock Agent test-agent-name is using guardrail test-guardrail-id to protect agent sessions."
            )
            assert result[0].resource_id == "test-agent-id"
            assert (
                result[0].resource_arn
                == f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:agent/test-agent-id"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []
