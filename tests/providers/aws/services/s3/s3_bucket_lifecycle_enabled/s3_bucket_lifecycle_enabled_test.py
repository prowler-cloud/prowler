from unittest import mock
from unittest.mock import patch

from moto import mock_aws

from prowler.providers.aws.services.s3.s3_service import S3, Bucket, LifeCycleRule
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_s3_bucket_lifecycle_enabled:
    @mock_aws
    def test_no_buckets(self):
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_no_mfa_delete.s3_bucket_no_mfa_delete.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_no_mfa_delete.s3_bucket_no_mfa_delete import (
                    s3_bucket_no_mfa_delete,
                )

                check = s3_bucket_no_mfa_delete()
                result = check.execute()

                assert len(result) == 0

    def test_no_lifecycle_configuration(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_bucket_lifecycle_enabled.s3_bucket_lifecycle_enabled.s3_client",
            new=S3(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_bucket_lifecycle_enabled.s3_bucket_lifecycle_enabled import (
                s3_bucket_lifecycle_enabled,
            )

            bucket_name = "bucket-test"
            bucket_arn = f"arn:aws:s3::{AWS_ACCOUNT_NUMBER}:{bucket_name}"
            s3_client = mock.MagicMock()
            s3_client.buckets = {
                bucket_arn: Bucket(
                    name=bucket_name,
                    region=AWS_REGION_US_EAST_1,
                )
            }

            with patch(
                "prowler.providers.aws.services.s3.s3_bucket_lifecycle_enabled.s3_bucket_lifecycle_enabled.s3_client",
                s3_client,
            ):
                check = s3_bucket_lifecycle_enabled()
                result = check.execute()

                # ALL REGIONS
                assert len(result) == 1

                # AWS_REGION_US_EAST_1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name} does not have a lifecycle configuration enabled."
                )
                assert result[0].resource_id == bucket_name
                assert result[0].resource_arn == bucket_arn
                assert result[0].region == AWS_REGION_US_EAST_1

    def test_one_valid_lifecycle_configuration(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_bucket_lifecycle_enabled.s3_bucket_lifecycle_enabled.s3_client",
            new=S3(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_bucket_lifecycle_enabled.s3_bucket_lifecycle_enabled import (
                s3_bucket_lifecycle_enabled,
            )

            s3_client = mock.MagicMock()
            bucket_name = "bucket-test"
            bucket_arn = f"arn:aws:s3::{AWS_ACCOUNT_NUMBER}:{bucket_name}"
            s3_client.buckets = {
                bucket_arn: Bucket(
                    name=bucket_name,
                    region=AWS_REGION_US_EAST_1,
                    lifecycle=[
                        LifeCycleRule(
                            id="test-rule-1",
                            status="Enabled",
                        ),
                    ],
                )
            }

            with patch(
                "prowler.providers.aws.services.s3.s3_bucket_lifecycle_enabled.s3_bucket_lifecycle_enabled.s3_client",
                s3_client,
            ):
                check = s3_bucket_lifecycle_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name} has a lifecycle configuration enabled."
                )
                assert result[0].resource_id == bucket_name
                assert result[0].resource_arn == bucket_arn
                assert result[0].region == AWS_REGION_US_EAST_1

    def test_several_lifecycle_configurations(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_bucket_lifecycle_enabled.s3_bucket_lifecycle_enabled.s3_client",
            new=S3(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_bucket_lifecycle_enabled.s3_bucket_lifecycle_enabled import (
                s3_bucket_lifecycle_enabled,
            )

            s3_client = mock.MagicMock()
            bucket_name = "bucket-test"
            bucket_arn = f"arn:aws:s3::{AWS_ACCOUNT_NUMBER}:{bucket_name}"
            s3_client.buckets = {
                bucket_arn: Bucket(
                    name=bucket_name,
                    region=AWS_REGION_US_EAST_1,
                    lifecycle=[
                        LifeCycleRule(
                            id="test-rule-1",
                            status="Disabled",
                        ),
                        LifeCycleRule(
                            id="test-rule-2",
                            status="Enabled",
                        ),
                    ],
                )
            }

            with patch(
                "prowler.providers.aws.services.s3.s3_bucket_lifecycle_enabled.s3_bucket_lifecycle_enabled.s3_client",
                s3_client,
            ):
                check = s3_bucket_lifecycle_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name} has a lifecycle configuration enabled."
                )
                assert result[0].resource_id == bucket_name
                assert result[0].resource_arn == bucket_arn
                assert result[0].region == AWS_REGION_US_EAST_1
