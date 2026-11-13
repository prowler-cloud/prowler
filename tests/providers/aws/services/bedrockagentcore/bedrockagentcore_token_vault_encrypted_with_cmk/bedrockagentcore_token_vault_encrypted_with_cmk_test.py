from contextlib import contextmanager
from datetime import datetime, timezone
from itertools import permutations
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
    AWS_REGION_CN_NORTH_1,
    AWS_REGION_CN_NORTHWEST_1,
    AWS_REGION_EU_CENTRAL_1,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_EU_WEST_2,
    AWS_REGION_US_EAST_1,
    AWS_REGION_US_WEST_2,
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
OTHER_ACCOUNT = "210987654321"
AWS_REGION_CA_CENTRAL_1 = "ca-central-1"
AWS_REGION_AP_NORTHEAST_1 = "ap-northeast-1"


def _vault_arn(region, vault_id=VAULT_ID, partition="aws", account=AWS_ACCOUNT_NUMBER):
    """Build a token-vault ARN in the collector's format."""
    return (
        f"arn:{partition}:bedrock-agentcore:{region}:{account}:token-vault/{vault_id}"
    )


def _read_failure(code="AccessDeniedException"):
    """Build a GetTokenVault client error with the given code."""
    return ClientError(
        {"Error": {"Code": code, "Message": "read failed"}}, "GetTokenVault"
    )


def _assert_regional_manual(
    finding, region, error, partition="aws", account=AWS_ACCOUNT_NUMBER
):
    """Assert the regional MANUAL identity and text for an unreadable vault."""
    assert finding.status == "MANUAL"
    assert (
        finding.status_extended
        == f"Bedrock AgentCore token vault could not be retrieved in region {region} ({error}); verify access to GetTokenVault and manually confirm whether the vault uses a customer-managed KMS key."
    )
    assert finding.resource_id == "token-vault/unknown"
    assert finding.resource_arn == _vault_arn(
        region, "unknown", partition=partition, account=account
    )
    assert finding.region == region


def _assert_customer_managed_pass(finding, region=AWS_REGION_US_EAST_1):
    """Assert the PASS identity and text for a collected customer-managed vault."""
    assert finding.status == "PASS"
    assert (
        finding.status_extended
        == f"Bedrock AgentCore token vault {VAULT_ID} is encrypted with a customer-managed KMS key in region {region}."
    )
    assert finding.resource_id == VAULT_ID
    assert finding.resource_arn == _vault_arn(region)
    assert finding.region == region


def _vault_response(key_type):
    """Build a validated token-vault response for a supported key type."""
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
    """Collect service state from mocked regional token-vault responses."""
    empty_list_responses = {
        "ListMemories": {"memories": []},
        "ListGateways": {"items": []},
        "ListAgentRuntimes": {"agentRuntimes": []},
        "ListBrowsers": {"browserSummaries": []},
        "ListCodeInterpreters": {"codeInterpreterSummaries": []},
    }

    def mock_make_api_call(client, operation_name, api_params):
        """Supply AgentCore responses and delegate unrelated API calls."""
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
    """Execute the check with the collected service bound to its client."""
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
        """Report PASS with the collected vault identity for a customer-managed key."""
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
        """Preserve the collector's existing ResourceNotFoundException suppression."""
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
        """Report read failures as regional MANUAL findings with error codes."""
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
        """Keep unavailable detail MANUAL even when cached key data suggests PASS."""
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
        """Report the documented omitted configuration as AWS-owned encryption."""
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
        """Report FAIL for an AWS-owned key whose response has no KMS key ARN."""
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
        """Keep an empty configuration MANUAL instead of assuming a key type."""
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
        """Treat empty or future key-type values as MANUAL compatibility cases."""
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
        """Preserve unexpected read exceptions as regional MANUAL findings."""
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
        """Preserve the collector's existing ValidationException suppression."""
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
        """Report malformed configuration types as regional collection failures."""
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
        """Keep PASS, FAIL, and MANUAL findings tied to their respective regions."""
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
        """Apply exact ARN filtering while an empty filter includes the vault."""
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
        """Retain a regional read error when a concrete vault ARN is filtered."""
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
        """Use the audited partition and account for real and unknown vault ARNs."""
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

    @mock_aws
    def test_selected_vault_excludes_read_error_from_unselected_region(self):
        """Drop a read error from a Region where no selected vault can exist."""
        with _collect_token_vault(
            {
                AWS_REGION_US_EAST_1: _vault_response("CustomerManagedKey"),
                AWS_REGION_EU_WEST_1: _read_failure(),
            },
            audit_resources=[VAULT_ARN],
        ) as service:
            assert set(service.token_vaults) == {VAULT_ARN}
            assert service.token_vaults_scan_errors == {
                AWS_REGION_EU_WEST_1: "AccessDeniedException"
            }
            result = _execute_check(service)

        assert len(result) == 1
        _assert_customer_managed_pass(result[0])

    @pytest.mark.parametrize(
        "unrelated_arn",
        [
            f"arn:aws:ec2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:instance/i-0123456789abcdef0",
            f"arn:aws:bedrock-agentcore:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:runtime/agent-0123456789",
            f"arn:aws:bedrock-agentcore:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:token-vaults/{VAULT_ID}",
            _vault_arn(AWS_REGION_EU_WEST_1, account=OTHER_ACCOUNT),
            _vault_arn(AWS_REGION_EU_WEST_1, partition="aws-cn"),
            _vault_arn(AWS_REGION_EU_WEST_1, vault_id=""),
            f"arn:aws:bedrock-agentcore:{AWS_REGION_EU_WEST_1}",
            # Not a TokenVaultIdType (1-64 of [a-zA-Z0-9-_]), so no read can return it.
            _vault_arn(
                AWS_REGION_EU_WEST_1, vault_id="default/oauth2credentialprovider/google"
            ),
            _vault_arn(AWS_REGION_EU_WEST_1, vault_id="default/"),
            _vault_arn(AWS_REGION_EU_WEST_1, vault_id="default.vault"),
            _vault_arn(AWS_REGION_EU_WEST_1, vault_id="*"),
            _vault_arn(AWS_REGION_EU_WEST_1, vault_id="a" * 65),
            _vault_arn(AWS_REGION_EU_WEST_1, vault_id="default\n"),
        ],
        ids=[
            "other-service",
            "other-agentcore-type",
            "lookalike-type",
            "other-account",
            "other-partition",
            "empty-vault-id",
            "truncated-arn",
            "nested-child",
            "trailing-separator",
            "invalid-character",
            "wildcard",
            "too-long-id",
            "trailing-newline",
        ],
    )
    @mock_aws
    def test_unrelated_selected_arn_does_not_widen_error_scope(self, unrelated_arn):
        """Keep a read error only for an ARN that can identify this account's vault."""
        with _collect_token_vault(
            {
                AWS_REGION_US_EAST_1: _vault_response("CustomerManagedKey"),
                AWS_REGION_EU_WEST_1: _read_failure(),
            },
            audit_resources=[VAULT_ARN, unrelated_arn],
        ) as service:
            assert set(service.token_vaults) == {VAULT_ARN}
            assert service.token_vaults_scan_errors == {
                AWS_REGION_EU_WEST_1: "AccessDeniedException"
            }
            result = _execute_check(service)

        assert len(result) == 1
        _assert_customer_managed_pass(result[0])

    @pytest.mark.parametrize(
        "audit_resources",
        [
            [
                f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:instance/i-0123456789abcdef0"
            ],
            [
                f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:runtime/agent-0123456789"
            ],
        ],
        ids=["other-service", "other-agentcore-type"],
    )
    @mock_aws
    def test_selection_without_vault_reports_nothing(self, audit_resources):
        """Report no vault finding when the selection names no token vault."""
        with _collect_token_vault(
            {
                AWS_REGION_US_EAST_1: _read_failure(),
                AWS_REGION_EU_WEST_1: _vault_response("CustomerManagedKey"),
            },
            audit_resources=audit_resources,
        ) as service:
            assert service.token_vaults == {}
            assert service.token_vaults_scan_errors == {
                AWS_REGION_US_EAST_1: "AccessDeniedException"
            }
            result = _execute_check(service)

        assert result == []

    @pytest.mark.parametrize(
        "selected_vault_id",
        [VAULT_ID, "other", "Vault-01_x", "a" * 64],
        ids=["default", "other", "hyphen-underscore-id", "max-length-id"],
    )
    @mock_aws
    def test_selected_vault_region_keeps_read_error(self, selected_vault_id):
        """Keep a read error for any selected vault ID in that Region, before vaults."""
        with _collect_token_vault(
            {
                AWS_REGION_US_EAST_1: _vault_response("CustomerManagedKey"),
                AWS_REGION_EU_WEST_1: _read_failure("ThrottlingException"),
            },
            audit_resources=[
                VAULT_ARN,
                _vault_arn(AWS_REGION_EU_WEST_1, vault_id=selected_vault_id),
            ],
        ) as service:
            result = _execute_check(service)

        assert len(result) == 2
        _assert_regional_manual(result[0], AWS_REGION_EU_WEST_1, "ThrottlingException")
        _assert_customer_managed_pass(result[1])

    @mock_aws
    def test_error_scope_uses_audited_partition_and_account(self):
        """Match selected vault ARNs against the audited partition and account."""
        with _collect_token_vault(
            {
                AWS_REGION_CN_NORTH_1: _read_failure(),
                AWS_REGION_CN_NORTHWEST_1: _read_failure(),
            },
            audit_resources=[
                _vault_arn(
                    AWS_REGION_CN_NORTH_1, partition="aws-cn", account=OTHER_ACCOUNT
                )
            ],
            partition="aws-cn",
            account=OTHER_ACCOUNT,
        ) as service:
            assert service.token_vaults_scan_errors == {
                AWS_REGION_CN_NORTH_1: "AccessDeniedException",
                AWS_REGION_CN_NORTHWEST_1: "AccessDeniedException",
            }
            result = _execute_check(service)

        assert len(result) == 1
        _assert_regional_manual(
            result[0],
            AWS_REGION_CN_NORTH_1,
            "AccessDeniedException",
            partition="aws-cn",
            account=OTHER_ACCOUNT,
        )

    @pytest.mark.parametrize("audit_resources", [None, []], ids=["unset", "empty"])
    @mock_aws
    def test_no_selected_arn_reports_every_regional_error(self, audit_resources):
        """Report every regional error in Region order, then vaults, for a full scan."""
        with _collect_token_vault(
            {
                AWS_REGION_US_EAST_1: _vault_response("CustomerManagedKey"),
                AWS_REGION_EU_WEST_2: RuntimeError("read failed"),
                AWS_REGION_EU_WEST_1: _read_failure(),
            },
            audit_resources=audit_resources,
        ) as service:
            result = _execute_check(service)

        assert len(result) == 3
        _assert_regional_manual(
            result[0], AWS_REGION_EU_WEST_1, "AccessDeniedException"
        )
        _assert_regional_manual(result[1], AWS_REGION_EU_WEST_2, "RuntimeError")
        _assert_customer_managed_pass(result[2])

    @mock_aws
    def test_regional_errors_are_sorted_for_every_insertion_order(self):
        """Report selected regional errors in Region order for any collected order."""
        errors = {
            AWS_REGION_US_EAST_1: "AccessDeniedException",
            AWS_REGION_EU_WEST_2: "RuntimeError",
            AWS_REGION_EU_WEST_1: "ThrottlingException",
        }
        expected_order = [
            AWS_REGION_EU_WEST_1,
            AWS_REGION_EU_WEST_2,
            AWS_REGION_US_EAST_1,
        ]
        with _collect_token_vault(
            {
                AWS_REGION_US_EAST_1: _read_failure(),
                AWS_REGION_EU_WEST_2: RuntimeError("read failed"),
                AWS_REGION_EU_WEST_1: _read_failure("ThrottlingException"),
            },
            audit_resources=[_vault_arn(region) for region in errors],
        ) as service:
            assert service.token_vaults == {}
            assert service.token_vaults_scan_errors == errors
            # The collector's insertion order follows thread completion and is not
            # fixed, so replay every order the check could receive.
            for insertion_order in permutations(errors):
                service.token_vaults_scan_errors = {
                    region: errors[region] for region in insertion_order
                }
                result = _execute_check(service)

                regions = [finding.region for finding in result]
                assert regions == expected_order
                for finding, region in zip(result, expected_order):
                    _assert_regional_manual(finding, region, errors[region])

    @mock_aws
    def test_mixed_service_selection_scopes_vaults_and_errors(self):
        """Scope successes and each failure kind to selected vaults across Regions."""
        malformed = _vault_response("ServiceManagedKey")
        malformed["kmsConfiguration"] = "invalid"
        aws_owned_arn = _vault_arn(AWS_REGION_CA_CENTRAL_1)
        with _collect_token_vault(
            {
                AWS_REGION_US_EAST_1: _read_failure(),
                AWS_REGION_EU_WEST_2: malformed,
                AWS_REGION_CA_CENTRAL_1: _vault_response("ServiceManagedKey"),
                AWS_REGION_EU_WEST_1: RuntimeError("read failed"),
                AWS_REGION_US_WEST_2: _read_failure("ThrottlingException"),
                AWS_REGION_EU_CENTRAL_1: _read_failure(),
                AWS_REGION_AP_NORTHEAST_1: _vault_response("CustomerManagedKey"),
            },
            audit_resources=[
                VAULT_ARN,
                _vault_arn(AWS_REGION_EU_WEST_2),
                aws_owned_arn,
                f"arn:aws:ec2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:instance/i-0123456789abcdef0",
                f"arn:aws:bedrock-agentcore:{AWS_REGION_US_WEST_2}:{AWS_ACCOUNT_NUMBER}:runtime/agent-0123456789",
            ],
        ) as service:
            # The collector omits the unselected ap-northeast-1 vault and keeps every error.
            assert set(service.token_vaults) == {aws_owned_arn}
            assert service.token_vaults_scan_errors == {
                AWS_REGION_US_EAST_1: "AccessDeniedException",
                AWS_REGION_EU_WEST_2: "AttributeError",
                AWS_REGION_EU_WEST_1: "RuntimeError",
                AWS_REGION_US_WEST_2: "ThrottlingException",
                AWS_REGION_EU_CENTRAL_1: "AccessDeniedException",
            }
            result = _execute_check(service)

        assert len(result) == 3
        _assert_regional_manual(result[0], AWS_REGION_EU_WEST_2, "AttributeError")
        _assert_regional_manual(
            result[1], AWS_REGION_US_EAST_1, "AccessDeniedException"
        )
        assert result[2].status == "FAIL"
        assert (
            result[2].status_extended
            == f"Bedrock AgentCore token vault {VAULT_ID} is encrypted with the default AWS-owned key instead of a customer-managed KMS key in region {AWS_REGION_CA_CENTRAL_1}."
        )
        assert result[2].resource_id == VAULT_ID
        assert result[2].resource_arn == aws_owned_arn
        assert result[2].region == AWS_REGION_CA_CENTRAL_1
