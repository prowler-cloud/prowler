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

MODEL_NAME = "test-custom-model"
MODEL_ARN = f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:custom-model/example.base-v1/{MODEL_NAME}"
KMS_KEY_ARN = f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/test-key-id"
FOREIGN_ACCOUNT = "999999999999"
FOREIGN_MODEL_ARN = f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{FOREIGN_ACCOUNT}:custom-model/example.base-v1/foreign-model"

# Operations the Bedrock constructor calls that these tests do not exercise.
_UNUSED_OPERATIONS = (
    "GetModelInvocationLoggingConfiguration",
    "ListGuardrails",
    "GetGuardrail",
    "ListTagsForResource",
)


def _custom_model_mock(kms_key_arn=None, fail_get=False):
    """Build a _make_api_call replacement returning one custom model."""

    def _mock(self, operation_name, kwarg):
        if operation_name in _UNUSED_OPERATIONS:
            return {}
        if operation_name == "ListCustomModels":
            return {
                "modelSummaries": [
                    {"modelArn": MODEL_ARN, "modelName": MODEL_NAME},
                ]
            }
        if operation_name == "GetCustomModel":
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


_mock_with_cmk = _custom_model_mock(KMS_KEY_ARN)
_mock_without_cmk = _custom_model_mock(None)
_mock_empty_cmk = _custom_model_mock("")
_mock_unreadable = _custom_model_mock(fail_get=True)


def _mock_empty(self, operation_name, kwarg):
    """No custom models at all."""
    if operation_name in _UNUSED_OPERATIONS:
        return {}
    if operation_name == "ListCustomModels":
        return {"modelSummaries": []}
    return make_api_call(self, operation_name, kwarg)


def _mock_unsupported_region(self, operation_name, kwarg):
    """The API is not available in the audited region."""
    if operation_name in _UNUSED_OPERATIONS:
        return {}
    if operation_name == "ListCustomModels":
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


def _mock_list_denied(self, operation_name, kwarg):
    """ListCustomModels is denied, so the region's models are unknown."""
    if operation_name in _UNUSED_OPERATIONS:
        return {}
    if operation_name == "ListCustomModels":
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


def _mock_shared_in_model(self, operation_name, kwarg):
    """Assert isOwned=True is sent, and return a model only when it is.

    A caller that omits isOwned would also receive models shared into this
    account through RAM, whose KMS key this account cannot set.
    """
    if operation_name in _UNUSED_OPERATIONS:
        return {}
    if operation_name == "ListCustomModels":
        if kwarg.get("isOwned") is not True:
            # What the API would return without the filter: a foreign-owned
            # model this account cannot remediate.
            return {
                "modelSummaries": [
                    {
                        "modelArn": FOREIGN_MODEL_ARN,
                        "modelName": "foreign-model",
                        "ownerAccountId": FOREIGN_ACCOUNT,
                    }
                ]
            }
        return {"modelSummaries": []}
    return make_api_call(self, operation_name, kwarg)


class Test_bedrock_custom_model_encrypted_with_cmk:
    """Unit tests for the bedrock_custom_model_encrypted_with_cmk check."""

    def _run(self):
        """Import the service + check under the active mocks and execute."""
        from prowler.providers.aws.services.bedrock.bedrock_service import Bedrock

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.bedrock.bedrock_custom_model_encrypted_with_cmk.bedrock_custom_model_encrypted_with_cmk.bedrock_client",
                new=Bedrock(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.bedrock.bedrock_custom_model_encrypted_with_cmk.bedrock_custom_model_encrypted_with_cmk import (
                bedrock_custom_model_encrypted_with_cmk,
            )

            return bedrock_custom_model_encrypted_with_cmk().execute()

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_empty)
    @mock_aws
    def test_no_resources(self):
        """No resources means no findings, not a spurious FAIL."""
        assert self._run() == []

    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=_mock_unsupported_region
    )
    @mock_aws
    def test_region_not_supported(self):
        """A ValidationException from the region must not raise; it yields no findings."""
        assert self._run() == []

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_with_cmk)
    @mock_aws
    def test_cmk_present_passes(self):
        """A model with modelKmsKeyArn set is compliant."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == MODEL_NAME
        assert result[0].resource_arn == MODEL_ARN
        assert result[0].region == AWS_REGION_US_EAST_1
        assert (
            result[0].status_extended
            == f"Bedrock custom model {MODEL_NAME} is encrypted with a customer-managed KMS key in region {AWS_REGION_US_EAST_1}."
        )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_without_cmk)
    @mock_aws
    def test_no_cmk_fails(self):
        """An absent modelKmsKeyArn means an AWS-owned key is in use."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "is not encrypted with a customer-managed KMS key" in (
            result[0].status_extended
        )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_empty_cmk)
    @mock_aws
    def test_empty_cmk_fails(self):
        """An empty modelKmsKeyArn string is not a key."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "is not encrypted with a customer-managed KMS key" in (
            result[0].status_extended
        )

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_unreadable)
    @mock_aws
    def test_detail_unreadable_is_manual_not_pass(self):
        """A failed GetCustomModel must not be reported as compliant."""
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "could not be retrieved" in result[0].status_extended

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_list_denied)
    @mock_aws
    def test_list_denied_is_manual_not_silence(self):
        """A denied ListCustomModels must report MANUAL, not vanish.

        Without a region-level report the region is indistinguishable from one
        that genuinely holds no custom models.
        """
        result = self._run()
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].resource_id == "custom-model/unknown"
        assert (
            result[0].resource_arn
            == f"arn:aws:bedrock:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:custom-model/unknown"
        )
        assert "could not be listed" in result[0].status_extended
        assert "AccessDeniedException" in result[0].status_extended
        assert result[0].status_extended.endswith(".")

    @mock.patch("botocore.client.BaseClient._make_api_call", new=_mock_shared_in_model)
    @mock_aws
    def test_shared_in_models_are_not_audited(self):
        """ListCustomModels must be called with isOwned=True.

        The mock returns a foreign-owned model only when the filter is absent, so
        a regression that drops isOwned produces a FAIL naming another account's
        model — a finding this account cannot remediate.
        """
        result = self._run()
        assert result == []

    def test_every_model_state_resolves_correctly(self):
        """Exhaust the decision space instead of sampling it.

        A Bedrock custom model cannot be created without a model customization
        job, so this check's behaviour is pinned by enumerating every combination
        of retrieval outcome, key value (absent, empty, set) and regional listing
        outcome, and asserting the per-model verdict plus the presence of the
        region-level report.

        Each case is driven through the real Bedrock service so a renamed service
        attribute breaks the test rather than passing silently.
        """
        from itertools import product

        for key, fail_get, list_denied in product(
            [None, "", KMS_KEY_ARN], [False, True], [False, True]
        ):
            case = (key, fail_get, list_denied)
            stub = (
                _mock_list_denied
                if list_denied
                else _custom_model_mock(key, fail_get=fail_get)
            )
            with mock.patch("botocore.client.BaseClient._make_api_call", new=stub):
                with mock_aws():
                    result = self._run()

            per_model = [
                r for r in result if "custom-model/unknown" not in r.resource_arn
            ]
            region_level = [
                r for r in result if "custom-model/unknown" in r.resource_arn
            ]

            if list_denied:
                # No model reaches the inventory; only the region-level report.
                assert per_model == [], case
                assert len(region_level) == 1, case
                assert region_level[0].status == "MANUAL", case
            else:
                assert len(per_model) == 1, case
                expected = "MANUAL" if fail_get else ("PASS" if key else "FAIL")
                assert per_model[0].status == expected, case
                assert region_level == [], case
            assert all(r.status_extended.endswith(".") for r in result), case
