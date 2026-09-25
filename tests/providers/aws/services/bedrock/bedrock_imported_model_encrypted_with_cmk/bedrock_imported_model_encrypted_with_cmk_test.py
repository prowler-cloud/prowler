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

MODEL_NAME = "test-imported-model"
MODEL_ID = "a1b2c3d4e5f6"
MODEL_ARN = f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:imported-model/{MODEL_ID}"
KMS_KEY_ARN = f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/11111111-2222-3333-4444-555555555555"


def _mock_empty(self, operation_name, kwarg):
    """Return no resources from the Bedrock APIs used during construction."""
    if operation_name in (
        "GetModelInvocationLoggingConfiguration",
        "ListGuardrails",
        "GetGuardrail",
        "ListTagsForResource",
        "ListCustomModels",
    ):
        return {}
    if operation_name == "ListImportedModels":
        return {"modelSummaries": []}
    return make_api_call(self, operation_name, kwarg)


def _imported_model_mock(kms_key_arn=None, fail_get=False):
    """Build a Bedrock API stub returning one imported model."""

    def _mock(self, operation_name, kwarg):
        if operation_name in (
            "GetModelInvocationLoggingConfiguration",
            "ListGuardrails",
            "GetGuardrail",
            "ListTagsForResource",
            "ListCustomModels",
        ):
            return {}
        if operation_name == "ListImportedModels":
            return {
                "modelSummaries": [
                    {"modelArn": MODEL_ARN, "modelName": MODEL_NAME},
                ]
            }
        if operation_name == "GetImportedModel":
            if fail_get:
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                    operation_name,
                )
            response = {"modelArn": MODEL_ARN, "modelName": MODEL_NAME}
            if kms_key_arn is not None:
                response["modelKmsKeyArn"] = kms_key_arn
            return response
        return make_api_call(self, operation_name, kwarg)

    return _mock


_mock_with_cmk = _imported_model_mock(KMS_KEY_ARN)
_mock_without_cmk = _imported_model_mock()
_mock_empty_cmk = _imported_model_mock("")
_mock_unreadable = _imported_model_mock(fail_get=True)


def _mock_list_denied(self, operation_name, kwarg):
    """Deny ListImportedModels while allowing unrelated Bedrock calls."""
    if operation_name in (
        "GetModelInvocationLoggingConfiguration",
        "ListGuardrails",
        "GetGuardrail",
        "ListTagsForResource",
        "ListCustomModels",
    ):
        return {}
    if operation_name == "ListImportedModels":
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


def _mock_unsupported_region(self, operation_name, kwarg):
    """Report that the imported-model API is unavailable in this region."""
    if operation_name in (
        "GetModelInvocationLoggingConfiguration",
        "ListGuardrails",
        "GetGuardrail",
        "ListTagsForResource",
        "ListCustomModels",
    ):
        return {}
    if operation_name == "ListImportedModels":
        raise ClientError(
            {
                "Error": {
                    "Code": "ValidationException",
                    "Message": "Bedrock is not supported in this region.",
                }
            },
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


def _mock_two_models(self, operation_name, kwarg):
    """Return two imported models with different encryption states."""
    second_name = "model-without-cmk"
    second_arn = f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:imported-model/f6e5d4c3b2a1"
    if operation_name in (
        "GetModelInvocationLoggingConfiguration",
        "ListGuardrails",
        "GetGuardrail",
        "ListTagsForResource",
        "ListCustomModels",
    ):
        return {}
    if operation_name == "ListImportedModels":
        return {
            "modelSummaries": [
                {"modelArn": MODEL_ARN, "modelName": MODEL_NAME},
                {"modelArn": second_arn, "modelName": second_name},
            ]
        }
    if operation_name == "GetImportedModel":
        if kwarg["modelIdentifier"] == MODEL_ARN:
            return {
                "modelArn": MODEL_ARN,
                "modelName": MODEL_NAME,
                "modelKmsKeyArn": KMS_KEY_ARN,
            }
        return {"modelArn": second_arn, "modelName": second_name}
    return make_api_call(self, operation_name, kwarg)


class Test_bedrock_imported_model_encrypted_with_cmk:
    """Unit tests for the imported-model CMK check."""

    def _run(self, audit_resources=None):
        """Import the service and check under active mocks, then execute."""
        from prowler.providers.aws.services.bedrock.bedrock_service import Bedrock

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        if audit_resources is not None:
            aws_provider._audit_resources = audit_resources
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_imported_model_encrypted_with_cmk.bedrock_imported_model_encrypted_with_cmk.bedrock_client",
                new=Bedrock(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_imported_model_encrypted_with_cmk.bedrock_imported_model_encrypted_with_cmk import (
                bedrock_imported_model_encrypted_with_cmk,
            )

            return bedrock_imported_model_encrypted_with_cmk().execute()

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_empty)
    @mock_aws
    def test_no_resources(self):
        """No imported models means no findings."""
        assert self._run() == []

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_unsupported_region
    )
    @mock_aws
    def test_region_not_supported(self):
        """An unsupported region produces no false finding."""
        assert self._run() == []

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_with_cmk)
    @mock_aws
    def test_cmk_present_passes(self):
        """An imported model with modelKmsKeyArn is compliant."""
        result = self._run()

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == MODEL_NAME
        assert result[0].resource_arn == MODEL_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
        assert (
            result[0].status_extended
            == f"Bedrock imported model {MODEL_NAME} is encrypted with a customer-managed KMS key in region {AWS_REGION_US_EAST_1}."
        )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_with_cmk)
    @mock_aws
    def test_out_of_scope_model_is_not_reported(self):
        """Resource scoping excludes imported models outside the requested ARNs."""
        other_model_arn = f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:imported-model/ffffffffffff"

        assert self._run(audit_resources=[other_model_arn]) == []

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_two_models)
    @mock_aws
    def test_each_model_is_evaluated_independently(self):
        """Mixed imported-model inventory produces one verdict per resource."""
        result = self._run()

        assert len(result) == 2
        assert {report.resource_id: report.status for report in result} == {
            MODEL_NAME: "PASS",
            "model-without-cmk": "FAIL",
        }

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_without_cmk)
    @mock_aws
    def test_no_cmk_fails(self):
        """An absent modelKmsKeyArn means an AWS-owned key is in use."""
        result = self._run()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Bedrock imported model {MODEL_NAME} is not encrypted with a customer-managed KMS key in region {AWS_REGION_US_EAST_1}."
        )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_empty_cmk)
    @mock_aws
    def test_empty_cmk_fails(self):
        """An empty modelKmsKeyArn is not a configured key."""
        result = self._run()

        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_unreadable)
    @mock_aws
    def test_detail_unreadable_is_manual(self):
        """A failed GetImportedModel call must not become a false FAIL."""
        result = self._run()

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"Bedrock imported model {MODEL_NAME} encryption configuration could not be retrieved in region {AWS_REGION_US_EAST_1}; verify manually that it uses a customer-managed KMS key."
        )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_list_denied)
    @mock_aws
    def test_list_denied_is_manual(self):
        """A denied imported-model inventory must produce a regional finding."""
        result = self._run()

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].resource_id == "imported-model/unknown"
        assert (
            result[0].resource_arn
            == f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:imported-model/unknown"
        )
        assert "AccessDeniedException" in result[0].status_extended
