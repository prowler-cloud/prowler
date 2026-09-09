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

RUNTIME_ID = "runtime-12345"
RUNTIME_NAME = "test-runtime"
RUNTIME_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:runtime/{RUNTIME_ID}"
ROLE_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/service-role/agentcore-role"
DISCOVERY_URL = "https://auth.example.com/.well-known/openid-configuration"

_UNUSED_OPERATIONS = ("ListTagsForResource",)


def _agent_runtime_mock(custom_jwt=None, request_header_allowlist=None, fail_get=False):
    def _mock(self, operation_name, kwarg):
        if operation_name in _UNUSED_OPERATIONS:
            return {"tags": {}}
        if operation_name == "ListAgentRuntimes":
            return {
                "agentRuntimes": [
                    {
                        "agentRuntimeId": RUNTIME_ID,
                        "agentRuntimeName": RUNTIME_NAME,
                        "agentRuntimeArn": RUNTIME_ARN,
                        "agentRuntimeVersion": "1.0",
                        "status": "ACTIVE",
                    }
                ]
            }
        if operation_name == "GetAgentRuntime":
            if fail_get:
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                    operation_name,
                )
            response = {
                "agentRuntimeId": RUNTIME_ID,
                "agentRuntimeName": RUNTIME_NAME,
                "agentRuntimeArn": RUNTIME_ARN,
                "agentRuntimeVersion": "1.0",
                "roleArn": ROLE_ARN,
                "status": "ACTIVE",
            }
            if custom_jwt is not None:
                response["authorizerConfiguration"] = {
                    "customJWTAuthorizer": custom_jwt
                }
            else:
                response["authorizerConfiguration"] = {}

            if request_header_allowlist is not None:
                response["requestHeaderConfiguration"] = {
                    "requestHeaderAllowlist": request_header_allowlist
                }
            else:
                response["requestHeaderConfiguration"] = {}
            return response
        return make_api_call(self, operation_name, kwarg)

    return _mock


_mock_pass = _agent_runtime_mock(
    custom_jwt={
        "discoveryUrl": DISCOVERY_URL,
        "allowedAudience": ["aud1"],
        "allowedClients": ["client1"],
    },
    request_header_allowlist=["Authorization"],
)
_mock_pass_case_insensitive = _agent_runtime_mock(
    custom_jwt={
        "discoveryUrl": DISCOVERY_URL,
        "allowedAudience": ["aud1"],
        "allowedClients": ["client1"],
    },
    request_header_allowlist=["authorization"],
)
_mock_without_jwt = _agent_runtime_mock(
    custom_jwt=None,
    request_header_allowlist=["Authorization"],
)
_mock_without_header_allowlist = _agent_runtime_mock(
    custom_jwt={
        "discoveryUrl": DISCOVERY_URL,
        "allowedAudience": ["aud1"],
        "allowedClients": ["client1"],
    },
    request_header_allowlist=["X-Custom-Header"],
)
_mock_empty_headers = _agent_runtime_mock(
    custom_jwt={
        "discoveryUrl": DISCOVERY_URL,
        "allowedAudience": ["aud1"],
        "allowedClients": ["client1"],
    },
    request_header_allowlist=None,
)
_mock_unreadable = _agent_runtime_mock(fail_get=True)


def _mock_empty(self, operation_name, kwarg):
    if operation_name in _UNUSED_OPERATIONS:
        return {"tags": {}}
    if operation_name == "ListAgentRuntimes":
        return {"agentRuntimes": []}
    return make_api_call(self, operation_name, kwarg)


def _mock_unsupported_region(self, operation_name, kwarg):
    if operation_name in _UNUSED_OPERATIONS:
        return {"tags": {}}
    if operation_name == "ListAgentRuntimes":
        raise ClientError(
            {
                "Error": {
                    "Code": "ValidationException",
                    "Message": "Service not supported in this region.",
                }
            },
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


def _mock_list_denied(self, operation_name, kwarg):
    if operation_name in _UNUSED_OPERATIONS:
        return {"tags": {}}
    if operation_name == "ListAgentRuntimes":
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


class Test_bedrockagentcore_runtime_jwt_identity_propagation_configured:
    def _run(self):
        from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
            BedrockAgentCore,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_runtime_jwt_identity_propagation_configured.bedrockagentcore_runtime_jwt_identity_propagation_configured.bedrockagentcore_client",
                new=BedrockAgentCore(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_runtime_jwt_identity_propagation_configured.bedrockagentcore_runtime_jwt_identity_propagation_configured import (
                bedrockagentcore_runtime_jwt_identity_propagation_configured,
            )

            return (
                bedrockagentcore_runtime_jwt_identity_propagation_configured().execute()
            )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_empty)
    @mock_aws
    def test_no_resources(self):
        assert self._run() == []

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_unsupported_region
    )
    @mock_aws
    def test_region_not_supported(self):
        assert self._run() == []

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_pass)
    @mock_aws
    def test_jwt_authorizer_and_allowlist_passes(self):
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == RUNTIME_ID
        assert result[0].resource_arn == RUNTIME_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore runtime {RUNTIME_NAME} is configured with a custom JWT authorizer and downstream identity propagation in region {AWS_REGION_US_EAST_1}."
        )

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_pass_case_insensitive
    )
    @mock_aws
    def test_jwt_authorizer_and_allowlist_case_insensitive_passes(self):
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == RUNTIME_ID
        assert result[0].resource_arn == RUNTIME_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore runtime {RUNTIME_NAME} is configured with a custom JWT authorizer and downstream identity propagation in region {AWS_REGION_US_EAST_1}."
        )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_without_jwt)
    @mock_aws
    def test_jwt_authorizer_missing_fails(self):
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_id == RUNTIME_ID
        assert result[0].resource_arn == RUNTIME_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore runtime {RUNTIME_NAME} does not have a custom JWT authorizer and downstream identity propagation configured and relies solely on the execution role in region {AWS_REGION_US_EAST_1}."
        )

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_without_header_allowlist
    )
    @mock_aws
    def test_header_allowlist_missing_authorization_fails(self):
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_id == RUNTIME_ID
        assert result[0].resource_arn == RUNTIME_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore runtime {RUNTIME_NAME} does not have a custom JWT authorizer and downstream identity propagation configured and relies solely on the execution role in region {AWS_REGION_US_EAST_1}."
        )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_empty_headers)
    @mock_aws
    def test_header_configuration_missing_fails(self):
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_id == RUNTIME_ID
        assert result[0].resource_arn == RUNTIME_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore runtime {RUNTIME_NAME} does not have a custom JWT authorizer and downstream identity propagation configured and relies solely on the execution role in region {AWS_REGION_US_EAST_1}."
        )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_unreadable)
    @mock_aws
    def test_get_agent_runtime_denied_manual(self):
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == RUNTIME_ID
        assert result[0].resource_arn == RUNTIME_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore runtime {RUNTIME_NAME} configuration could not be retrieved in region {AWS_REGION_US_EAST_1}; verify manually that it is configured with a custom JWT authorizer and downstream identity propagation."
        )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_list_denied)
    @mock_aws
    def test_list_agent_runtimes_denied_manual(self):
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == "runtime/unknown"
        assert (
            result[0].resource_arn
            == f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:runtime/unknown"
        )
        assert result[0].region == AWS_REGION_US_EAST_1
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore runtimes could not be listed in region {AWS_REGION_US_EAST_1} (AccessDeniedException); verify manually that every runtime is configured with a custom JWT authorizer and downstream identity propagation."
        )
