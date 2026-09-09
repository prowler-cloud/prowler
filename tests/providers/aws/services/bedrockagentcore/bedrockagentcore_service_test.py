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
ROLE_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/service-role/agentcore-role"
DISCOVERY_URL = "https://auth.example.com/.well-known/openid-configuration"


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListAgentRuntimes":
        return {
            "agentRuntimes": [
                {
                    "agentRuntimeId": RUNTIME_ID,
                    "agentRuntimeName": RUNTIME_NAME,
                    "agentRuntimeArn": RUNTIME_ARN,
                    "agentRuntimeVersion": "1.0",
                    "status": "ACTIVE",
                    "description": "Test Runtime",
                }
            ]
        }
    elif operation_name == "GetAgentRuntime":
        return {
            "agentRuntimeId": RUNTIME_ID,
            "agentRuntimeName": RUNTIME_NAME,
            "agentRuntimeArn": RUNTIME_ARN,
            "agentRuntimeVersion": "1.0",
            "status": "ACTIVE",
            "roleArn": ROLE_ARN,
            "description": "Test Runtime",
            "authorizerConfiguration": {
                "customJWTAuthorizer": {
                    "discoveryUrl": DISCOVERY_URL,
                    "allowedAudience": ["my-audience"],
                    "allowedClients": ["client-1"],
                }
            },
            "requestHeaderConfiguration": {"requestHeaderAllowlist": ["Authorization"]},
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
        assert runtime.version == "1.0"
        assert runtime.status == "ACTIVE"
        assert runtime.role_arn == ROLE_ARN
        assert runtime.detail_retrieved is True
        assert runtime.authorizer_configuration is not None
        assert runtime.authorizer_configuration.custom_jwt_authorizer is not None
        assert (
            runtime.authorizer_configuration.custom_jwt_authorizer.discovery_url
            == DISCOVERY_URL
        )
        assert (
            runtime.authorizer_configuration.custom_jwt_authorizer.allowed_audiences
            == ["my-audience"]
        )
        assert (
            runtime.authorizer_configuration.custom_jwt_authorizer.allowed_clients
            == ["client-1"]
        )
        assert runtime.request_header_configuration is not None
        assert runtime.request_header_configuration.request_header_allowlist == [
            "Authorization"
        ]
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
            assert "us-east-1" in bedrockagentcore.agent_runtimes_scan_errors
            assert (
                bedrockagentcore.agent_runtimes_scan_errors["us-east-1"]
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
            "botocore.client.BaseClient._make_api_call", new=mock_unsupported_api_call
        ):
            aws_provider = set_mocked_aws_provider(
                audited_regions=[AWS_REGION_US_EAST_1]
            )
            bedrockagentcore = BedrockAgentCore(aws_provider)
            assert len(bedrockagentcore.agent_runtimes) == 0
            assert "us-east-1" not in bedrockagentcore.agent_runtimes_scan_errors
