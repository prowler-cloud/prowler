from unittest import mock

from prowler.providers.aws.services.sagemaker.sagemaker_service import FeatureGroup
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

CHECK_PATH = "prowler.providers.aws.services.sagemaker.sagemaker_feature_group_offline_store_encrypted_with_cmk.sagemaker_feature_group_offline_store_encrypted_with_cmk"

feature_group_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:feature-group/fg-test"
kms_key = f"arn:aws:kms:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:key/abcd-1234"


def _run_check(sagemaker_client, aws_provider):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(f"{CHECK_PATH}.sagemaker_client", sagemaker_client),
    ):
        from prowler.providers.aws.services.sagemaker.sagemaker_feature_group_offline_store_encrypted_with_cmk.sagemaker_feature_group_offline_store_encrypted_with_cmk import (
            sagemaker_feature_group_offline_store_encrypted_with_cmk,
        )

        return sagemaker_feature_group_offline_store_encrypted_with_cmk().execute()


class Test_sagemaker_feature_group_offline_store_encrypted_with_cmk:
    def test_no_feature_groups(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_feature_groups = []

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        result = _run_check(sagemaker_client, aws_provider)

        assert len(result) == 0

    def test_offline_store_encrypted_with_cmk(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_feature_groups = [
            FeatureGroup(
                name="fg-test",
                region=AWS_REGION_EU_WEST_1,
                arn=feature_group_arn,
                offline_store_enabled=True,
                offline_store_kms_key_id=kms_key,
            )
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        result = _run_check(sagemaker_client, aws_provider)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "SageMaker Feature Group fg-test has its offline store encrypted with a "
            "KMS Customer Managed Key."
        )
        assert result[0].resource_id == "fg-test"
        assert result[0].resource_arn == feature_group_arn
        assert result[0].region == AWS_REGION_EU_WEST_1

    def test_offline_store_not_encrypted_with_cmk(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_feature_groups = [
            FeatureGroup(
                name="fg-test",
                region=AWS_REGION_EU_WEST_1,
                arn=feature_group_arn,
                offline_store_enabled=True,
                offline_store_kms_key_id=None,
            )
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        result = _run_check(sagemaker_client, aws_provider)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "SageMaker Feature Group fg-test has an offline store that is not encrypted "
            "with a KMS Customer Managed Key."
        )
        assert result[0].resource_id == "fg-test"
        assert result[0].resource_arn == feature_group_arn

    def test_feature_group_without_offline_store_skipped(self):
        sagemaker_client = mock.MagicMock
        sagemaker_client.sagemaker_feature_groups = [
            FeatureGroup(
                name="fg-online-only",
                region=AWS_REGION_EU_WEST_1,
                arn=feature_group_arn,
                offline_store_enabled=False,
                offline_store_kms_key_id=None,
            )
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        result = _run_check(sagemaker_client, aws_provider)

        # Feature groups without an offline store are out of scope -> no findings.
        assert len(result) == 0
