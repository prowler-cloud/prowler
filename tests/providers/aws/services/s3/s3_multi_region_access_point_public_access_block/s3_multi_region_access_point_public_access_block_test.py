from unittest import mock
from unittest.mock import patch

import botocore
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_WEST_2,
    set_mocked_aws_provider,
)

MRAP_NAME = "test-mrap"
BUCKET_NAME = "test-bucket"

# Original botocore _make_api_call function
orig = botocore.client.BaseClient._make_api_call


# Mocked botocore _make_api_call function
def mock_make_api_call_pab_enabled(self, operation_name, kwarg):
    if operation_name == "ListMultiRegionAccessPoints":
        return {
            "AccessPoints": [
                {
                    "Name": MRAP_NAME,
                    "Regions": [
                        {
                            "Bucket": BUCKET_NAME,
                            "Region": "us-west-2",
                        }
                    ],
                    "PublicAccessBlock": {
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    },
                }
            ]
        }
    # If we don't want to patch the API call
    return orig(self, operation_name, kwarg)


def mock_make_api_call_pab_disabled(self, operation_name, kwarg):
    if operation_name == "ListMultiRegionAccessPoints":
        return {
            "AccessPoints": [
                {
                    "Name": MRAP_NAME,
                    "Regions": [
                        {
                            "Bucket": BUCKET_NAME,
                            "Region": "us-west-2",
                        }
                    ],
                    "PublicAccessBlock": {
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": False,
                        "BlockPublicPolicy": False,
                        "RestrictPublicBuckets": False,
                    },
                }
            ]
        }
    # If we don't want to patch the API call
    return orig(self, operation_name, kwarg)


def mock_make_api_call_pab_one_disabled(self, operation_name, kwarg):
    if operation_name == "ListMultiRegionAccessPoints":
        return {
            "AccessPoints": [
                {
                    "Name": MRAP_NAME,
                    "Regions": [
                        {
                            "Bucket": BUCKET_NAME,
                            "Region": "us-west-2",
                        }
                    ],
                    "PublicAccessBlock": {
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    },
                }
            ]
        }
    # If we don't want to patch the API call
    return orig(self, operation_name, kwarg)


class Test_s3_multi_region_access_point_public_access_block:
    @mock_aws
    def test_no_multi_region_access_points(self):
        from prowler.providers.aws.services.s3.s3_service import S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_WEST_2])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_multi_region_access_point_public_access_block.s3_multi_region_access_point_public_access_block.s3control_client",
                new=S3Control(aws_provider),
            ):
                from prowler.providers.aws.services.s3.s3_multi_region_access_point_public_access_block.s3_multi_region_access_point_public_access_block import (
                    s3_multi_region_access_point_public_access_block,
                )

                check = s3_multi_region_access_point_public_access_block()
                result = check.execute()

                assert len(result) == 0

    @patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_pab_enabled
    )
    def test_multi_region_access_points_with_public_access_block(self):
        from prowler.providers.aws.services.s3.s3_service import S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_WEST_2])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_multi_region_access_point_public_access_block.s3_multi_region_access_point_public_access_block.s3control_client",
                new=S3Control(aws_provider),
            ):
                from prowler.providers.aws.services.s3.s3_multi_region_access_point_public_access_block.s3_multi_region_access_point_public_access_block import (
                    s3_multi_region_access_point_public_access_block,
                )

                check = s3_multi_region_access_point_public_access_block()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"S3 Multi Region Access Point {MRAP_NAME} of buckets {BUCKET_NAME} does have Public Access Block enabled."
                )
                assert result[0].resource_id == MRAP_NAME
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3::{AWS_ACCOUNT_NUMBER}:accesspoint/{MRAP_NAME}"
                )

    @patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_pab_disabled
    )
    def test_multi_region_access_points_without_public_access_block(self):
        from prowler.providers.aws.services.s3.s3_service import S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_WEST_2])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_multi_region_access_point_public_access_block.s3_multi_region_access_point_public_access_block.s3control_client",
                new=S3Control(aws_provider),
            ):
                from prowler.providers.aws.services.s3.s3_multi_region_access_point_public_access_block.s3_multi_region_access_point_public_access_block import (
                    s3_multi_region_access_point_public_access_block,
                )

                check = s3_multi_region_access_point_public_access_block()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"S3 Multi Region Access Point {MRAP_NAME} of buckets {BUCKET_NAME} does not have Public Access Block enabled."
                )
                assert result[0].resource_id == MRAP_NAME
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3::{AWS_ACCOUNT_NUMBER}:accesspoint/{MRAP_NAME}"
                )

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_pab_one_disabled,
    )
    def test_multi_region_access_points_without_one_public_access_block(self):
        from prowler.providers.aws.services.s3.s3_service import S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_WEST_2])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_multi_region_access_point_public_access_block.s3_multi_region_access_point_public_access_block.s3control_client",
                new=S3Control(aws_provider),
            ):
                from prowler.providers.aws.services.s3.s3_multi_region_access_point_public_access_block.s3_multi_region_access_point_public_access_block import (
                    s3_multi_region_access_point_public_access_block,
                )

                check = s3_multi_region_access_point_public_access_block()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"S3 Multi Region Access Point {MRAP_NAME} of buckets {BUCKET_NAME} does not have Public Access Block enabled."
                )
                assert result[0].resource_id == MRAP_NAME
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3::{AWS_ACCOUNT_NUMBER}:accesspoint/{MRAP_NAME}"
                )
