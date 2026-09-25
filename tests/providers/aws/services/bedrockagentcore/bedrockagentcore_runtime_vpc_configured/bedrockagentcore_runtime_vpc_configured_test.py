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
SECOND_RUNTIME_ID = "runtime-67890"
SECOND_RUNTIME_NAME = "public-runtime"
SECOND_RUNTIME_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:runtime/{SECOND_RUNTIME_ID}"
SUBNET_ID = "subnet-0123456789abcdef0"
SECURITY_GROUP_ID = "sg-0123456789abcdef0"

_UNUSED_OPERATIONS = ("ListTagsForResource",)


def _agent_runtime_mock(
    network_mode="VPC",
    subnets=None,
    security_groups=None,
    fail_get=False,
    extra_runtimes=None,
):
    def _mock(self, operation_name, kwarg):
        if operation_name in _UNUSED_OPERATIONS:
            return {"tags": {}}
        if operation_name == "ListAgentRuntimes":
            runtimes = [
                {
                    "agentRuntimeId": RUNTIME_ID,
                    "agentRuntimeName": RUNTIME_NAME,
                    "agentRuntimeArn": RUNTIME_ARN,
                    "agentRuntimeVersion": "1",
                    "status": "READY",
                }
            ]
            if extra_runtimes:
                runtimes.extend(extra_runtimes)
            return {"agentRuntimes": runtimes}
        if operation_name == "GetAgentRuntime":
            if fail_get:
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                    operation_name,
                )
            requested_id = kwarg.get("agentRuntimeId", RUNTIME_ID)
            if extra_runtimes and requested_id == SECOND_RUNTIME_ID:
                return {
                    "agentRuntimeId": SECOND_RUNTIME_ID,
                    "agentRuntimeName": SECOND_RUNTIME_NAME,
                    "agentRuntimeArn": SECOND_RUNTIME_ARN,
                    "status": "READY",
                    "networkConfiguration": {"networkMode": "PUBLIC"},
                }
            response = {
                "agentRuntimeId": RUNTIME_ID,
                "agentRuntimeName": RUNTIME_NAME,
                "agentRuntimeArn": RUNTIME_ARN,
                "agentRuntimeVersion": "1",
                "status": "READY",
            }
            network_configuration = {"networkMode": network_mode}
            if subnets is not None or security_groups is not None:
                network_configuration["networkModeConfig"] = {
                    "subnets": subnets or [],
                    "securityGroups": security_groups or [],
                }
            response["networkConfiguration"] = network_configuration
            return response
        return make_api_call(self, operation_name, kwarg)

    return _mock


_mock_pass = _agent_runtime_mock(
    network_mode="VPC",
    subnets=[SUBNET_ID],
    security_groups=[SECURITY_GROUP_ID],
)
_mock_public = _agent_runtime_mock(network_mode="PUBLIC")
_mock_missing_network = _agent_runtime_mock(network_mode=None)
_mock_vpc_missing_subnets = _agent_runtime_mock(
    network_mode="VPC",
    subnets=[],
    security_groups=[SECURITY_GROUP_ID],
)
_mock_vpc_missing_security_groups = _agent_runtime_mock(
    network_mode="VPC",
    subnets=[SUBNET_ID],
    security_groups=[],
)
_mock_vpc_missing_config = _agent_runtime_mock(network_mode="VPC")
_mock_unreadable = _agent_runtime_mock(fail_get=True)
_mock_mixed = _agent_runtime_mock(
    network_mode="VPC",
    subnets=[SUBNET_ID],
    security_groups=[SECURITY_GROUP_ID],
    extra_runtimes=[
        {
            "agentRuntimeId": SECOND_RUNTIME_ID,
            "agentRuntimeName": SECOND_RUNTIME_NAME,
            "agentRuntimeArn": SECOND_RUNTIME_ARN,
            "status": "READY",
        }
    ],
)


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


class Test_bedrockagentcore_runtime_vpc_configured:
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
                "prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_runtime_vpc_configured.bedrockagentcore_runtime_vpc_configured.bedrockagentcore_client",
                new=BedrockAgentCore(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_runtime_vpc_configured.bedrockagentcore_runtime_vpc_configured import (
                bedrockagentcore_runtime_vpc_configured,
            )

            return bedrockagentcore_runtime_vpc_configured().execute()

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
    def test_vpc_configured_passes(self):
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == RUNTIME_ID
        assert result[0].resource_arn == RUNTIME_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore runtime {RUNTIME_NAME} is configured with VPC network mode and has subnets and security groups in region {AWS_REGION_US_EAST_1}."
        )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_public)
    @mock_aws
    def test_public_network_mode_fails(self):
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_id == RUNTIME_ID
        assert result[0].resource_arn == RUNTIME_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore runtime {RUNTIME_NAME} is configured with PUBLIC network mode instead of VPC in region {AWS_REGION_US_EAST_1}."
        )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_missing_network)
    @mock_aws
    def test_missing_network_mode_fails(self):
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore runtime {RUNTIME_NAME} is configured with PUBLIC network mode instead of VPC in region {AWS_REGION_US_EAST_1}."
        )

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_vpc_missing_subnets
    )
    @mock_aws
    def test_vpc_mode_missing_subnets_fails(self):
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore runtime {RUNTIME_NAME} uses VPC network mode but is missing required subnets or security groups in region {AWS_REGION_US_EAST_1}."
        )

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=_mock_vpc_missing_security_groups,
    )
    @mock_aws
    def test_vpc_mode_missing_security_groups_fails(self):
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore runtime {RUNTIME_NAME} uses VPC network mode but is missing required subnets or security groups in region {AWS_REGION_US_EAST_1}."
        )

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_vpc_missing_config
    )
    @mock_aws
    def test_vpc_mode_missing_network_mode_config_fails(self):
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore runtime {RUNTIME_NAME} uses VPC network mode but is missing required subnets or security groups in region {AWS_REGION_US_EAST_1}."
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
            == f"Bedrock AgentCore runtime {RUNTIME_NAME} network configuration could not be retrieved in region {AWS_REGION_US_EAST_1}; verify manually that it uses VPC network mode with subnets and security groups."
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
            == f"Bedrock AgentCore runtimes could not be listed in region {AWS_REGION_US_EAST_1} (AccessDeniedException); verify manually that every runtime uses VPC network mode with subnets and security groups."
        )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_mixed)
    @mock_aws
    def test_mixed_runtimes_report_only_in_scope_findings(self):
        result = self._run()
        assert len(result) == 2
        findings = {finding.resource_id: finding for finding in result}
        assert findings[RUNTIME_ID].status == "PASS"
        assert findings[SECOND_RUNTIME_ID].status == "FAIL"
        assert findings[SECOND_RUNTIME_ID].resource_arn == SECOND_RUNTIME_ARN
        assert (
            findings[SECOND_RUNTIME_ID].status_extended
            == f"Bedrock AgentCore runtime {SECOND_RUNTIME_NAME} is configured with PUBLIC network mode instead of VPC in region {AWS_REGION_US_EAST_1}."
        )
