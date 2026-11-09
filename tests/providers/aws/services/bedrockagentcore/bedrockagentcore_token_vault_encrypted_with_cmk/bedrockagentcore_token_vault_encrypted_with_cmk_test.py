from contextlib import contextmanager
from datetime import datetime, timezone
from unittest import mock

import botocore
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_service import (
    BedrockAgentCore,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    mocked_api_response,
    set_mocked_aws_provider,
)

MAKE_API_CALL = botocore.client.BaseClient._make_api_call
SERVICE_NAME = "bedrock-agentcore-control"
CLIENT_MODULE = (
    "prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_client"
)
CHECK_MODULE = (
    "prowler.providers.aws.services.bedrockagentcore."
    "bedrockagentcore_token_vault_encrypted_with_cmk."
    "bedrockagentcore_token_vault_encrypted_with_cmk"
)
VAULT_ID = "default"
VAULT_ARN = f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:token-vault/{VAULT_ID}"


def _vault_response(key_type):
    configuration = {"keyType": key_type}
    if key_type == "CustomerManagedKey":
        configuration["kmsKeyArn"] = (
            f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/12345678-1234-1234-1234-123456789012"
        )
    return mocked_api_response(
        SERVICE_NAME,
        "GetTokenVault",
        {
            "tokenVaultId": VAULT_ID,
            "kmsConfiguration": configuration,
            "lastModifiedDate": datetime(2026, 11, 9, tzinfo=timezone.utc),
        },
    )


@contextmanager
def _collect_token_vault(
    responses, *, audit_resources=None, partition="aws", account=AWS_ACCOUNT_NUMBER
):
    empty_list_responses = {
        "ListMemories": {"memories": []},
        "ListGateways": {"items": []},
        "ListAgentRuntimes": {"agentRuntimes": []},
        "ListBrowsers": {"browserSummaries": []},
        "ListCodeInterpreters": {"codeInterpreterSummaries": []},
    }

    def mock_make_api_call(client, operation_name, api_params):
        if client.meta.service_model.service_name == SERVICE_NAME:
            if operation_name == "GetTokenVault":
                response = responses[client.meta.region_name]
                if isinstance(response, Exception):
                    raise response
                return response
            if operation_name in empty_list_responses:
                return mocked_api_response(
                    SERVICE_NAME, operation_name, empty_list_responses[operation_name]
                )
        return MAKE_API_CALL(client, operation_name, api_params)

    aws_provider = set_mocked_aws_provider(
        list(responses),
        audited_account=account,
        audited_account_arn=f"arn:{partition}:iam::{account}:root",
        audited_partition=partition,
    )
    if audit_resources is not None:
        aws_provider._audit_resources = audit_resources
    with (
        mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call),
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
    ):
        yield BedrockAgentCore(aws_provider)


def _execute_check(service):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=service.provider,
        ),
        mock.patch(f"{CLIENT_MODULE}.bedrockagentcore_client", new=service),
        mock.patch(f"{CHECK_MODULE}.bedrockagentcore_client", new=service),
    ):
        from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_token_vault_encrypted_with_cmk.bedrockagentcore_token_vault_encrypted_with_cmk import (
            bedrockagentcore_token_vault_encrypted_with_cmk,
        )

        return bedrockagentcore_token_vault_encrypted_with_cmk().execute()


class Test_bedrockagentcore_token_vault_encrypted_with_cmk:
    @mock_aws
    def test_collected_customer_managed_key_passes(self):
        with _collect_token_vault(
            {AWS_REGION_US_EAST_1: _vault_response("CustomerManagedKey")}
        ) as service:
            result = _execute_check(service)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore token vault {VAULT_ID} is encrypted with a customer-managed KMS key in region {AWS_REGION_US_EAST_1}."
        )
        assert result[0].resource_id == VAULT_ID
        assert result[0].resource_arn == VAULT_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

        assert result[0].check_metadata.Severity == "low"

    @mock_aws
    def test_absent_vault_has_no_finding(self):
        error = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "absent"}},
            "GetTokenVault",
        )
        with _collect_token_vault({AWS_REGION_US_EAST_1: error}) as service:
            assert service.token_vaults == {}
            assert service.token_vaults_scan_errors == {}
            result = _execute_check(service)

        assert result == []

    @pytest.mark.parametrize(
        "error_code", ["AccessDeniedException", "ThrottlingException"]
    )
    @mock_aws
    def test_recorded_client_error_is_regional_manual(self, error_code):
        error = ClientError(
            {"Error": {"Code": error_code, "Message": "read failed"}},
            "GetTokenVault",
        )
        with _collect_token_vault({AWS_REGION_US_EAST_1: error}) as service:
            assert service.token_vaults == {}
            assert service.token_vaults_scan_errors == {
                AWS_REGION_US_EAST_1: error_code
            }
            result = _execute_check(service)
            assert service.token_vaults == {}

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore token vault could not be retrieved in region {AWS_REGION_US_EAST_1} ({error_code}); verify access to GetTokenVault and manually confirm whether the vault uses a customer-managed KMS key."
        )
        assert result[0].resource_id == "token-vault/unknown"
        assert (
            result[0].resource_arn
            == f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:token-vault/unknown"
        )
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].check_metadata.Severity == "low"

    @pytest.mark.parametrize("key_type", [None, "CustomerManagedKey"])
    @mock_aws
    def test_unretrieved_detail_is_manual_even_with_stale_key_type(self, key_type):
        with _collect_token_vault(
            {AWS_REGION_US_EAST_1: _vault_response("CustomerManagedKey")}
        ) as service:
            # Defensive modeled state: unverified cached data must not imply a PASS.
            service.token_vaults[VAULT_ARN].detail_retrieved = False
            service.token_vaults[VAULT_ARN].kms_key_type = key_type
            result = _execute_check(service)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore token vault {VAULT_ID} encryption configuration could not be retrieved in region {AWS_REGION_US_EAST_1}; verify manually whether it uses a customer-managed KMS key."
        )
        assert result[0].resource_id == VAULT_ID
        assert result[0].resource_arn == VAULT_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].check_metadata.Severity == "low"

    @mock_aws
    def test_documented_omitted_configuration_uses_aws_owned_key(self):
        response = _vault_response("ServiceManagedKey")
        del response["kmsConfiguration"]
        # The devguide documents omission for AWS-owned keys; the pinned model requires it.
        with pytest.raises(AssertionError, match="kmsConfiguration"):
            mocked_api_response(SERVICE_NAME, "GetTokenVault", response)

        with _collect_token_vault({AWS_REGION_US_EAST_1: response}) as service:
            assert service.token_vaults[VAULT_ARN].kms_key_type == "ServiceManagedKey"
            assert service.token_vaults[VAULT_ARN].detail_retrieved
            result = _execute_check(service)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore token vault {VAULT_ID} is encrypted with the default AWS-owned key instead of a customer-managed KMS key in region {AWS_REGION_US_EAST_1}."
        )
        assert result[0].resource_id == VAULT_ID
        assert result[0].resource_arn == VAULT_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].check_metadata.Severity == "low"

    @mock_aws
    def test_collected_aws_owned_key_fails_without_key_arn(self):
        response = _vault_response("ServiceManagedKey")
        assert "kmsKeyArn" not in response["kmsConfiguration"]
        with _collect_token_vault({AWS_REGION_US_EAST_1: response}) as service:
            result = _execute_check(service)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore token vault {VAULT_ID} is encrypted with the default AWS-owned key instead of a customer-managed KMS key in region {AWS_REGION_US_EAST_1}."
        )
        assert result[0].resource_id == VAULT_ID
        assert result[0].resource_arn == VAULT_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_present_configuration_without_key_type_is_manual(self):
        response = _vault_response("ServiceManagedKey")
        response["kmsConfiguration"] = {}
        # Deliberate malformed-response coverage, distinct from documented parent omission.
        with pytest.raises(AssertionError, match="keyType"):
            mocked_api_response(SERVICE_NAME, "GetTokenVault", response)

        with _collect_token_vault({AWS_REGION_US_EAST_1: response}) as service:
            assert service.token_vaults[VAULT_ARN].kms_key_type is None
            assert service.token_vaults[VAULT_ARN].detail_retrieved
            result = _execute_check(service)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore token vault {VAULT_ID} encryption key type is missing or unrecognized in region {AWS_REGION_US_EAST_1}; verify manually whether it uses a customer-managed KMS key."
        )
        assert result[0].resource_id == VAULT_ID
        assert result[0].resource_arn == VAULT_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    @pytest.mark.parametrize("key_type", ["UnexpectedFutureKey", ""])
    @mock_aws
    def test_unrecognized_key_type_is_manual(self, key_type):
        model = botocore.session.get_session().get_service_model(SERVICE_NAME)
        output_shape = model.operation_model("GetTokenVault").output_shape
        supported_key_types = (
            output_shape.members["kmsConfiguration"].members["keyType"].enum
        )
        assert key_type not in supported_key_types
        # Botocore validates structure, not enum values: these are deliberate drift inputs.
        response = _vault_response("ServiceManagedKey")
        response["kmsConfiguration"]["keyType"] = key_type
        mocked_api_response(SERVICE_NAME, "GetTokenVault", response)
        with _collect_token_vault({AWS_REGION_US_EAST_1: response}) as service:
            assert service.token_vaults[VAULT_ARN].detail_retrieved
            result = _execute_check(service)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore token vault {VAULT_ID} encryption key type is missing or unrecognized in region {AWS_REGION_US_EAST_1}; verify manually whether it uses a customer-managed KMS key."
        )
        assert result[0].resource_id == VAULT_ID
        assert result[0].resource_arn == VAULT_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    @pytest.mark.parametrize("error_type", [RuntimeError, ConnectionResetError])
    @mock_aws
    def test_unexpected_exception_is_regional_manual(self, error_type):
        with _collect_token_vault(
            {AWS_REGION_US_EAST_1: error_type("read failed")}
        ) as service:
            assert service.token_vaults == {}
            assert service.token_vaults_scan_errors == {
                AWS_REGION_US_EAST_1: error_type.__name__
            }
            result = _execute_check(service)
            assert service.token_vaults == {}

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore token vault could not be retrieved in region {AWS_REGION_US_EAST_1} ({error_type.__name__}); verify access to GetTokenVault and manually confirm whether the vault uses a customer-managed KMS key."
        )
        assert result[0].resource_id == "token-vault/unknown"
        assert (
            result[0].resource_arn
            == f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:token-vault/unknown"
        )
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_inherited_validation_exception_suppression_has_no_finding(self):
        error = ClientError(
            {
                "Error": {
                    "Code": "ValidationException",
                    "Message": "input constraints were not satisfied",
                }
            },
            "GetTokenVault",
        )
        with _collect_token_vault({AWS_REGION_US_EAST_1: error}) as service:
            assert service.token_vaults == {}
            assert service.token_vaults_scan_errors == {}
            result = _execute_check(service)

        assert result == []

    @pytest.mark.parametrize("configuration", [None, "invalid", []])
    @mock_aws
    def test_malformed_configuration_is_regional_manual(self, configuration):
        response = _vault_response("ServiceManagedKey")
        response["kmsConfiguration"] = configuration
        # Deliberately malformed parent values must not use the documented omission fallback.
        with pytest.raises(AssertionError, match="kmsConfiguration"):
            mocked_api_response(SERVICE_NAME, "GetTokenVault", response)

        with _collect_token_vault({AWS_REGION_US_EAST_1: response}) as service:
            assert service.token_vaults == {}
            assert service.token_vaults_scan_errors == {
                AWS_REGION_US_EAST_1: "AttributeError"
            }
            result = _execute_check(service)
            assert service.token_vaults == {}

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore token vault could not be retrieved in region {AWS_REGION_US_EAST_1} (AttributeError); verify access to GetTokenVault and manually confirm whether the vault uses a customer-managed KMS key."
        )
        assert result[0].resource_id == "token-vault/unknown"
        assert (
            result[0].resource_arn
            == f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:token-vault/unknown"
        )
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_multiple_regions_preserve_each_vault_and_error_identity(self):
        owned_region = "us-west-2"
        error_region = "eu-west-1"
        error_code = "AccessDeniedException"
        error = ClientError(
            {"Error": {"Code": error_code, "Message": "read failed"}},
            "GetTokenVault",
        )
        with _collect_token_vault(
            {
                AWS_REGION_US_EAST_1: _vault_response("CustomerManagedKey"),
                owned_region: _vault_response("ServiceManagedKey"),
                error_region: error,
            }
        ) as service:
            assert len(service.token_vaults) == 2
            assert service.token_vaults_scan_errors == {error_region: error_code}
            result = _execute_check(service)
            assert len(service.token_vaults) == 2

        assert len(result) == 3
        by_region = {finding.region: finding for finding in result}
        assert set(by_region) == {AWS_REGION_US_EAST_1, owned_region, error_region}
        assert by_region[AWS_REGION_US_EAST_1].status == "PASS"
        assert (
            by_region[AWS_REGION_US_EAST_1].status_extended
            == f"Bedrock AgentCore token vault {VAULT_ID} is encrypted with a customer-managed KMS key in region {AWS_REGION_US_EAST_1}."
        )
        assert by_region[AWS_REGION_US_EAST_1].resource_id == VAULT_ID
        assert by_region[AWS_REGION_US_EAST_1].resource_arn == VAULT_ARN
        assert by_region[owned_region].status == "FAIL"
        assert (
            by_region[owned_region].status_extended
            == f"Bedrock AgentCore token vault {VAULT_ID} is encrypted with the default AWS-owned key instead of a customer-managed KMS key in region {owned_region}."
        )
        assert by_region[owned_region].resource_id == VAULT_ID
        assert (
            by_region[owned_region].resource_arn
            == f"arn:aws:bedrock-agentcore:{owned_region}:{AWS_ACCOUNT_NUMBER}:token-vault/{VAULT_ID}"
        )
        assert by_region[error_region].status == "MANUAL"
        assert (
            by_region[error_region].status_extended
            == f"Bedrock AgentCore token vault could not be retrieved in region {error_region} ({error_code}); verify access to GetTokenVault and manually confirm whether the vault uses a customer-managed KMS key."
        )
        assert by_region[error_region].resource_id == "token-vault/unknown"
        assert (
            by_region[error_region].resource_arn
            == f"arn:aws:bedrock-agentcore:{error_region}:{AWS_ACCOUNT_NUMBER}:token-vault/unknown"
        )

    @pytest.mark.parametrize(
        "audit_resources, expected_count",
        [
            ([VAULT_ARN], 1),
            (
                [
                    f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:token-vault/other"
                ],
                0,
            ),
            ([], 1),
        ],
    )
    @mock_aws
    def test_successful_resource_filter_is_exact(self, audit_resources, expected_count):
        with _collect_token_vault(
            {AWS_REGION_US_EAST_1: _vault_response("CustomerManagedKey")},
            audit_resources=audit_resources,
        ) as service:
            assert len(service.token_vaults) == expected_count
            assert service.token_vaults_scan_errors == {}
            result = _execute_check(service)

        assert len(result) == expected_count
        if expected_count:
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Bedrock AgentCore token vault {VAULT_ID} is encrypted with a customer-managed KMS key in region {AWS_REGION_US_EAST_1}."
            )
            assert result[0].resource_id == VAULT_ID
            assert result[0].resource_arn == VAULT_ARN
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_concrete_resource_filter_preserves_regional_read_error(self):
        error_code = "AccessDeniedException"
        error = ClientError(
            {"Error": {"Code": error_code, "Message": "read failed"}},
            "GetTokenVault",
        )
        with _collect_token_vault(
            {AWS_REGION_US_EAST_1: error}, audit_resources=[VAULT_ARN]
        ) as service:
            assert service.token_vaults == {}
            assert service.token_vaults_scan_errors == {
                AWS_REGION_US_EAST_1: error_code
            }
            result = _execute_check(service)
            assert service.token_vaults == {}

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"Bedrock AgentCore token vault could not be retrieved in region {AWS_REGION_US_EAST_1} ({error_code}); verify access to GetTokenVault and manually confirm whether the vault uses a customer-managed KMS key."
        )
        assert result[0].resource_id == "token-vault/unknown"
        assert (
            result[0].resource_arn
            == f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:token-vault/unknown"
        )
        assert result[0].resource_arn != VAULT_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    @pytest.mark.parametrize("read_fails", [False, True])
    @mock_aws
    def test_audited_partition_and_account_define_resource_identity(self, read_fails):
        partition = "aws-cn"
        region = "cn-north-1"
        account = "210987654321"
        if read_fails:
            response = ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "read failed"}},
                "GetTokenVault",
            )
        else:
            response = _vault_response("CustomerManagedKey")
            response["kmsConfiguration"][
                "kmsKeyArn"
            ] = f"arn:{partition}:kms:{region}:{account}:key/12345678-1234-1234-1234-123456789012"
            mocked_api_response(SERVICE_NAME, "GetTokenVault", response)

        with _collect_token_vault(
            {region: response}, partition=partition, account=account
        ) as service:
            result = _execute_check(service)
            if read_fails:
                assert service.token_vaults == {}
                assert service.token_vaults_scan_errors == {
                    region: "AccessDeniedException"
                }
            else:
                assert set(service.token_vaults) == {
                    f"arn:{partition}:bedrock-agentcore:{region}:{account}:token-vault/{VAULT_ID}"
                }
                assert service.token_vaults_scan_errors == {}

        assert len(result) == 1
        assert result[0].region == region
        if read_fails:
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == f"Bedrock AgentCore token vault could not be retrieved in region {region} (AccessDeniedException); verify access to GetTokenVault and manually confirm whether the vault uses a customer-managed KMS key."
            )
            assert result[0].resource_id == "token-vault/unknown"
            assert (
                result[0].resource_arn
                == f"arn:{partition}:bedrock-agentcore:{region}:{account}:token-vault/unknown"
            )
        else:
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Bedrock AgentCore token vault {VAULT_ID} is encrypted with a customer-managed KMS key in region {region}."
            )
            assert result[0].resource_id == VAULT_ID
            assert (
                result[0].resource_arn
                == f"arn:{partition}:bedrock-agentcore:{region}:{account}:token-vault/{VAULT_ID}"
            )
