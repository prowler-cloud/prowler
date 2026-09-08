"""Service-level tests for the BedrockAgentCore collectors.

`docs/developer-guide/unit-testing.mdx` requires that every method within a service be
tested. These cover the six list collectors, the per-resource Get* enrichment, and the
error paths, independently of any single check.

NOTE ON MERGING: upstream keeps service tests in
`tests/providers/aws/services/bedrock/bedrock_service_test.py`. Fold the
`Test_Bedrock_AgentCore_Service` class below into that file rather than adding a second
service-test module — `sdk-check-duplicate-test-names.yml` fails on duplicate test
filenames across providers, and a second bedrock service-test file is needless drift.
"""

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

MEMORY_ID = "mem-123"
MEMORY_ARN = (
    f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}"
    f":memory/{MEMORY_ID}"
)
GATEWAY_ID = "gw-123"
RUNTIME_ID = "rt-123"
RUNTIME_ARN = (
    f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}"
    f":runtime/{RUNTIME_ID}"
)
KMS_KEY_ARN = f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/test-key-id"


def mock_make_api_call_agentcore(self, operation_name, kwarg):
    """Populate one resource per AgentCore collector."""
    if operation_name == "ListMemories":
        return {"memories": [{"arn": MEMORY_ARN, "id": MEMORY_ID, "name": "mem"}]}
    if operation_name == "GetMemory":
        return {
            "memory": {
                "id": MEMORY_ID,
                "name": "mem",
                "arn": MEMORY_ARN,
                "encryptionKeyArn": KMS_KEY_ARN,
            }
        }
    if operation_name == "ListGateways":
        return {"items": [{"gatewayId": GATEWAY_ID, "name": "gw"}]}
    if operation_name == "GetGateway":
        return {
            "gatewayId": GATEWAY_ID,
            "name": "gw",
            "authorizerType": "CUSTOM_JWT",
            "authorizerConfiguration": {
                "customJWTAuthorizer": {"allowedClients": ["client-1"]}
            },
        }
    if operation_name == "ListAgentRuntimes":
        return {
            "agentRuntimes": [
                {
                    "agentRuntimeArn": RUNTIME_ARN,
                    "agentRuntimeId": RUNTIME_ID,
                    "agentRuntimeName": "rt",
                }
            ]
        }
    if operation_name == "GetAgentRuntime":
        return {
            "agentRuntimeId": RUNTIME_ID,
            "agentRuntimeName": "rt",
            "agentRuntimeArn": RUNTIME_ARN,
            "networkConfiguration": {"networkMode": "VPC"},
        }
    if operation_name == "ListCodeInterpreters":
        return {
            "codeInterpreterSummaries": [
                {
                    "codeInterpreterArn": f"{RUNTIME_ARN}-ci",
                    "codeInterpreterId": "ci-1",
                    "name": "ci",
                }
            ]
        }
    if operation_name == "GetCodeInterpreter":
        return {
            "codeInterpreterId": "ci-1",
            "name": "ci",
            "networkConfiguration": {"networkMode": "SANDBOX"},
        }
    if operation_name == "ListBrowsers":
        return {
            "browserSummaries": [
                {
                    "browserArn": f"{RUNTIME_ARN}-br",
                    "browserId": "br-1",
                    "name": "br",
                }
            ]
        }
    if operation_name == "GetBrowser":
        return {
            "browserId": "br-1",
            "name": "br",
            "networkConfiguration": {"networkMode": "VPC"},
            "recording": {"enabled": True},
        }
    if operation_name == "GetTokenVault":
        return {
            "tokenVaultId": "default",
            "kmsConfiguration": {"keyType": "CustomerManagedKey"},
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_unsupported(self, operation_name, kwarg):
    """Every AgentCore collector raises — the service must degrade, not crash."""
    if operation_name.startswith(("List", "Get")) and (
        "Memor" in operation_name
        or "Gateway" in operation_name
        or "AgentRuntime" in operation_name
        or "CodeInterpreter" in operation_name
        or "Browser" in operation_name
        or "TokenVault" in operation_name
    ):
        raise ClientError(
            {
                "Error": {
                    "Code": "ValidationException",
                    "Message": "Bedrock AgentCore is not supported in this region.",
                }
            },
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


class Test_Bedrock_AgentCore_Service:
    """Cover the BedrockAgentCore service class."""

    @mock_aws
    def test_service_and_client(self):
        """The boto3 service name must be the CONTROL plane, not the data plane."""
        from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
            BedrockAgentCore,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        agentcore = BedrockAgentCore(aws_provider)
        assert agentcore.service == "bedrock-agentcore-control"
        assert agentcore.audited_account == AWS_ACCOUNT_NUMBER
        assert AWS_REGION_US_EAST_1 in agentcore.regional_clients

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_agentcore
    )
    @mock_aws
    def test_all_collectors_populate(self):
        """Each collector stores its resource and the Get* enrichment lands."""
        from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
            BedrockAgentCore,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        ac = BedrockAgentCore(aws_provider)

        assert len(ac.memories) == 1
        memory = next(iter(ac.memories.values()))
        assert memory.id == MEMORY_ID
        assert memory.arn == MEMORY_ARN
        assert memory.region == AWS_REGION_US_EAST_1
        assert memory.encryption_key_arn == KMS_KEY_ARN

        assert len(ac.gateways) == 1
        gateway = next(iter(ac.gateways.values()))
        assert gateway.id == GATEWAY_ID
        # The gateway ARN is CONSTRUCTED by the service; ListGateways does not return one.
        assert gateway.arn.endswith(f":gateway/{GATEWAY_ID}")
        assert gateway.authorizer_type == "CUSTOM_JWT"
        assert gateway.custom_jwt_allowed_clients == ["client-1"]

        assert len(ac.agent_runtimes) == 1
        runtime = next(iter(ac.agent_runtimes.values()))
        assert runtime.id == RUNTIME_ID
        assert runtime.arn == RUNTIME_ARN
        assert runtime.network_mode == "VPC"

        assert len(ac.code_interpreters) == 1
        assert next(iter(ac.code_interpreters.values())).network_mode == "SANDBOX"

        assert len(ac.browsers) == 1
        browser = next(iter(ac.browsers.values()))
        assert browser.recording_enabled is True
        assert browser.network_mode == "VPC"

        assert len(ac.token_vaults) == 1
        assert next(iter(ac.token_vaults.values())).kms_key_type == "CustomerManagedKey"

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_unsupported
    )
    @mock_aws
    def test_unsupported_region_degrades_quietly(self):
        """A per-collector ClientError is logged, not raised, and leaves stores empty."""
        from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
            BedrockAgentCore,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        ac = BedrockAgentCore(aws_provider)
        assert ac.memories == {}
        assert ac.gateways == {}
        assert ac.agent_runtimes == {}
        assert ac.code_interpreters == {}
        assert ac.browsers == {}
        assert ac.token_vaults == {}
