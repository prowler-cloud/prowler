from unittest import mock

import botocore
from botocore.exceptions import ClientError
from moto import mock_aws

from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
    BedrockAgentCore,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call

RUNTIME_ID = "runtime-12345"
RUNTIME_NAME = "test-runtime"
RUNTIME_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:runtime/{RUNTIME_ID}"
SUBNET_ID = "subnet-0123456789abcdef0"
SECURITY_GROUP_ID = "sg-0123456789abcdef0"


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListAgentRuntimes":
        return {
            "agentRuntimes": [
                {
                    "agentRuntimeId": RUNTIME_ID,
                    "agentRuntimeName": RUNTIME_NAME,
                    "agentRuntimeArn": RUNTIME_ARN,
                    "agentRuntimeVersion": "1",
                    "status": "READY",
                    "description": "Test Runtime",
                }
            ]
        }
    elif operation_name == "GetAgentRuntime":
        return {
            "agentRuntimeId": RUNTIME_ID,
            "agentRuntimeName": RUNTIME_NAME,
            "agentRuntimeArn": RUNTIME_ARN,
            "agentRuntimeVersion": "1",
            "status": "READY",
            "description": "Test Runtime",
            "networkConfiguration": {
                "networkMode": "VPC",
                "networkModeConfig": {
                    "subnets": [SUBNET_ID],
                    "securityGroups": [SECURITY_GROUP_ID],
                },
            },
        }
    elif operation_name == "ListTagsForResource":
        return {"tags": {"Environment": "Dev", "Owner": "Security"}}
    return make_api_call(self, operation_name, kwarg)


class Test_BedrockAgentCore_Service:
    @mock_aws
    def test_service(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        bedrockagentcore = BedrockAgentCore(aws_provider)
        assert bedrockagentcore.service == "bedrock-agentcore-control"

    @mock_aws
    def test_client(self):
        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        bedrockagentcore = BedrockAgentCore(aws_provider)
        for regional_client in bedrockagentcore.regional_clients.values():
            assert regional_client.__class__.__name__ == "BedrockAgentCoreControl"

    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_list_and_get_agent_runtimes(self):
        aws_provider = set_mocked_aws_provider(audited_regions=[AWS_REGION_US_EAST_1])
        bedrockagentcore = BedrockAgentCore(aws_provider)
        assert len(bedrockagentcore.agent_runtimes) == 1
        assert RUNTIME_ARN in bedrockagentcore.agent_runtimes
        runtime = bedrockagentcore.agent_runtimes[RUNTIME_ARN]
        assert runtime.id == RUNTIME_ID
        assert runtime.name == RUNTIME_NAME
        assert runtime.arn == RUNTIME_ARN
        assert runtime.version == "1"
        assert runtime.status == "READY"
        assert runtime.detail_retrieved is True
        assert runtime.network_mode == "VPC"
        assert runtime.network_mode_config is not None
        assert runtime.network_mode_config.subnets == [SUBNET_ID]
        assert runtime.network_mode_config.security_groups == [SECURITY_GROUP_ID]
        assert runtime.tags == {"Environment": "Dev", "Owner": "Security"}

    @mock_aws
    def test_list_agent_runtimes_scan_errors(self):
        def mock_error_api_call(self, operation_name, kwarg):
            if operation_name == "ListAgentRuntimes":
                raise ClientError(
                    {
                        "Error": {
                            "Code": "AccessDeniedException",
                            "Message": "Access Denied",
                        }
                    },
                    operation_name,
                )
            return make_api_call(self, operation_name, kwarg)

        with mock.patch(
            "botocore.client.BaseClient._make_api_call", new=mock_error_api_call
        ):
            aws_provider = set_mocked_aws_provider(
                audited_regions=[AWS_REGION_US_EAST_1]
            )
            bedrockagentcore = BedrockAgentCore(aws_provider)
            assert len(bedrockagentcore.agent_runtimes) == 0
            assert AWS_REGION_US_EAST_1 in bedrockagentcore.agent_runtimes_scan_errors
            assert (
                bedrockagentcore.agent_runtimes_scan_errors[AWS_REGION_US_EAST_1]
                == "AccessDeniedException"
            )

    @mock_aws
    def test_list_agent_runtimes_unsupported_region(self):
        def mock_unsupported_api_call(self, operation_name, kwarg):
            if operation_name == "ListAgentRuntimes":
                raise ClientError(
                    {
                        "Error": {
                            "Code": "ValidationException",
                            "Message": "Service not supported",
                        }
                    },
                    operation_name,
                )
            return make_api_call(self, operation_name, kwarg)

        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_unsupported_api_call,
        ):
            aws_provider = set_mocked_aws_provider(
                audited_regions=[AWS_REGION_US_EAST_1]
            )
            bedrockagentcore = BedrockAgentCore(aws_provider)
            assert len(bedrockagentcore.agent_runtimes) == 0
            assert (
                AWS_REGION_US_EAST_1 not in bedrockagentcore.agent_runtimes_scan_errors
            )

    @mock_aws
    def test_get_agent_runtime_denied_leaves_detail_unretrieved(self):
        def mock_get_denied(self, operation_name, kwarg):
            if operation_name == "ListAgentRuntimes":
                return {
                    "agentRuntimes": [
                        {
                            "agentRuntimeId": RUNTIME_ID,
                            "agentRuntimeName": RUNTIME_NAME,
                            "agentRuntimeArn": RUNTIME_ARN,
                            "status": "READY",
                        }
                    ]
                }
            if operation_name == "GetAgentRuntime":
                raise ClientError(
                    {
                        "Error": {
                            "Code": "AccessDeniedException",
                            "Message": "denied",
                        }
                    },
                    operation_name,
                )
            if operation_name == "ListTagsForResource":
                return {"tags": {}}
            return make_api_call(self, operation_name, kwarg)

        with mock.patch(
            "botocore.client.BaseClient._make_api_call", new=mock_get_denied
        ):
            aws_provider = set_mocked_aws_provider(
                audited_regions=[AWS_REGION_US_EAST_1]
            )
            bedrockagentcore = BedrockAgentCore(aws_provider)
            runtime = bedrockagentcore.agent_runtimes[RUNTIME_ARN]
            assert runtime.detail_retrieved is False
            assert runtime.network_mode is None
            assert runtime.network_mode_config is None
