from unittest import mock

import botocore
import botocore.client
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

mock_make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call_error(self, operation_name, kwarg):
    if operation_name == "PutPublicAccessBlock":
        raise botocore.exceptions.ClientError(
            {
                "Error": {
                    "Code": "InvalidPermission.NotFound",
                    "Message": "The specified rule does not exist in this security group.",
                }
            },
            operation_name,
        )
    return mock_make_api_call(self, operation_name, kwarg)


class Test_cloudtrail_logs_s3_bucket_is_not_publicly_accessible_fixer:
    @mock_aws
    def test_trail_bucket_public_acl(self):
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)
        s3_client.put_bucket_acl(
            AccessControlPolicy={
                "Grants": [
                    {
                        "Grantee": {
                            "DisplayName": "test",
                            "EmailAddress": "",
                            "ID": "test_ID",
                            "Type": "Group",
                            "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                        },
                        "Permission": "READ",
                    },
                ],
                "Owner": {"DisplayName": "test", "ID": "test_id"},
            },
            Bucket=bucket_name_us,
        )

        trail_name_us = "trail_test_us"
        cloudtrail_client = client("cloudtrail", region_name=AWS_REGION_US_EAST_1)
        cloudtrail_client.create_trail(
            Name=trail_name_us, S3BucketName=bucket_name_us, IsMultiRegionTrail=False
        )

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_is_not_publicly_accessible.cloudtrail_logs_s3_bucket_is_not_publicly_accessible_fixer.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_is_not_publicly_accessible.cloudtrail_logs_s3_bucket_is_not_publicly_accessible_fixer.s3_client",
                new=S3(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_is_not_publicly_accessible.cloudtrail_logs_s3_bucket_is_not_publicly_accessible_fixer import (
                fixer,
            )

            assert fixer(trail_name_us, AWS_REGION_US_EAST_1)

    @mock_aws
    def test_trail_bucket_public_acl_error(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_error
        ):
            aws_provider = set_mocked_aws_provider(
                [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
            )
            s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
            bucket_name_us = "bucket_test_us"
            s3_client.create_bucket(Bucket=bucket_name_us)
            s3_client.put_bucket_acl(
                AccessControlPolicy={
                    "Grants": [
                        {
                            "Grantee": {
                                "DisplayName": "test",
                                "EmailAddress": "",
                                "ID": "test_ID",
                                "Type": "Group",
                                "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                            },
                            "Permission": "READ",
                        },
                    ],
                    "Owner": {"DisplayName": "test", "ID": "test_id"},
                },
                Bucket=bucket_name_us,
            )

            trail_name_us = "trail_test_us"
            cloudtrail_client = client("cloudtrail", region_name=AWS_REGION_US_EAST_1)
            cloudtrail_client.create_trail(
                Name=trail_name_us,
                S3BucketName=bucket_name_us,
                IsMultiRegionTrail=False,
            )

            from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
                Cloudtrail,
            )
            from prowler.providers.aws.services.s3.s3_service import S3

            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_is_not_publicly_accessible.cloudtrail_logs_s3_bucket_is_not_publicly_accessible_fixer.cloudtrail_client",
                    new=Cloudtrail(aws_provider),
                ),
                mock.patch(
                    "prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_is_not_publicly_accessible.cloudtrail_logs_s3_bucket_is_not_publicly_accessible_fixer.s3_client",
                    new=S3(aws_provider),
                ),
            ):
                # Test Check
                from prowler.providers.aws.services.cloudtrail.cloudtrail_logs_s3_bucket_is_not_publicly_accessible.cloudtrail_logs_s3_bucket_is_not_publicly_accessible_fixer import (
                    fixer,
                )

                assert not fixer(trail_name_us, AWS_REGION_US_EAST_1)
