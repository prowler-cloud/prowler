from unittest import mock

from prowler.providers.aws.services.sagemaker.sagemaker_service import FeatureGroup
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

feature_group_name = "test-feature-group"
feature_group_arn = f"arn:aws:sagemaker:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:feature-group/{feature_group_name}"
kms_key_arn = f"arn:aws:kms:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:key/1234abcd-12ab-34cd-56ef-1234567890ab"

CHECK_MODULE = "prowler.providers.aws.services.sagemaker.sagemaker_feature_group_offline_store_encrypted_with_cmk.sagemaker_feature_group_offline_store_encrypted_with_cmk"


def run_check(feature_groups):
    sagemaker_client = mock.MagicMock
    sagemaker_client.feature_groups = {fg.arn: fg for fg in feature_groups}

    aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(f"{CHECK_MODULE}.sagemaker_client", sagemaker_client),
    ):
        from prowler.providers.aws.services.sagemaker.sagemaker_feature_group_offline_store_encrypted_with_cmk.sagemaker_feature_group_offline_store_encrypted_with_cmk import (
            sagemaker_feature_group_offline_store_encrypted_with_cmk,
        )

        return sagemaker_feature_group_offline_store_encrypted_with_cmk().execute()


class Test_sagemaker_feature_group_offline_store_encrypted_with_cmk:
    def test_no_feature_groups(self):
        assert run_check([]) == []

    def test_offline_store_with_kms_key(self):
        result = run_check(
            [
                FeatureGroup(
                    name=feature_group_name,
                    arn=feature_group_arn,
                    region=AWS_REGION_EU_WEST_1,
                    describe_succeeded=True,
                    offline_store_enabled=True,
                    offline_store_kms_key_id=kms_key_arn,
                )
            ]
        )

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"SageMaker Feature Group {feature_group_name} offline store is encrypted with KMS key {kms_key_arn}."
        )
        assert result[0].resource_id == feature_group_name
        assert result[0].resource_arn == feature_group_arn
        assert result[0].region == AWS_REGION_EU_WEST_1

    def test_offline_store_without_kms_key(self):
        result = run_check(
            [
                FeatureGroup(
                    name=feature_group_name,
                    arn=feature_group_arn,
                    region=AWS_REGION_EU_WEST_1,
                    describe_succeeded=True,
                    offline_store_enabled=True,
                )
            ]
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"SageMaker Feature Group {feature_group_name} offline store is not encrypted with a customer-managed KMS key."
        )
        assert result[0].resource_arn == feature_group_arn

    def test_online_only_feature_group_is_not_reported(self):
        result = run_check(
            [
                FeatureGroup(
                    name=feature_group_name,
                    arn=feature_group_arn,
                    region=AWS_REGION_EU_WEST_1,
                    describe_succeeded=True,
                    offline_store_enabled=False,
                )
            ]
        )

        assert result == []

    def test_describe_failed_is_manual(self):
        result = run_check(
            [
                FeatureGroup(
                    name=feature_group_name,
                    arn=feature_group_arn,
                    region=AWS_REGION_EU_WEST_1,
                )
            ]
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "sagemaker:DescribeFeatureGroup" in result[0].status_extended
        assert result[0].resource_arn == feature_group_arn
