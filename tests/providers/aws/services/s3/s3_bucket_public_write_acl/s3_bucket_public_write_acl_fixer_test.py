from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_s3_bucket_public_write_acl_fixer:
    @mock_aws
    def test_bucket_public_write_ACL_AllUsers_WRITE(self):
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)
        bucket_owner = s3_client.get_bucket_acl(Bucket=bucket_name_us)["Owner"]
        # Generate S3Control Client
        s3control_client = client("s3control", region_name=AWS_REGION_US_EAST_1)
        s3control_client.put_public_access_block(
            AccountId=AWS_ACCOUNT_NUMBER,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        s3_client.put_public_access_block(
            Bucket=bucket_name_us,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        s3_client.put_bucket_acl(
            Bucket=bucket_name_us,
            AccessControlPolicy={
                "Grants": [
                    {
                        "Grantee": {
                            "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                            "Type": "Group",
                        },
                        "Permission": "WRITE",
                    },
                ],
                "Owner": bucket_owner,
            },
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl_fixer.s3_client",
                new=S3(aws_provider),
            ):
                # Test Fixer
                from prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl_fixer import (
                    fixer,
                )

                assert fixer(bucket_name_us, AWS_REGION_US_EAST_1)

    @mock_aws
    def test_bucket_public_write_ACL_AllUsers_WRITE_ACP(self):
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)
        bucket_owner = s3_client.get_bucket_acl(Bucket=bucket_name_us)["Owner"]
        # Generate S3Control Client
        s3control_client = client("s3control", region_name=AWS_REGION_US_EAST_1)
        s3control_client.put_public_access_block(
            AccountId=AWS_ACCOUNT_NUMBER,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        s3_client.put_public_access_block(
            Bucket=bucket_name_us,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        s3_client.put_bucket_acl(
            Bucket=bucket_name_us,
            AccessControlPolicy={
                "Grants": [
                    {
                        "Grantee": {
                            "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                            "Type": "Group",
                        },
                        "Permission": "WRITE_ACP",
                    },
                ],
                "Owner": bucket_owner,
            },
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl_fixer.s3_client",
                new=S3(aws_provider),
            ):
                # Test Fixer
                from prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl_fixer import (
                    fixer,
                )

                assert fixer(bucket_name_us, AWS_REGION_US_EAST_1)

    @mock_aws
    def test_bucket_public_write_ACL_AllUsers_FULL_CONTROL(self):
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)
        bucket_owner = s3_client.get_bucket_acl(Bucket=bucket_name_us)["Owner"]
        # Generate S3Control Client
        s3control_client = client("s3control", region_name=AWS_REGION_US_EAST_1)
        s3control_client.put_public_access_block(
            AccountId=AWS_ACCOUNT_NUMBER,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        s3_client.put_public_access_block(
            Bucket=bucket_name_us,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        s3_client.put_bucket_acl(
            Bucket=bucket_name_us,
            AccessControlPolicy={
                "Grants": [
                    {
                        "Grantee": {
                            "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                            "Type": "Group",
                        },
                        "Permission": "FULL_CONTROL",
                    },
                ],
                "Owner": bucket_owner,
            },
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl_fixer.s3_client",
                new=S3(aws_provider),
            ):
                # Test Fixer
                from prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl_fixer import (
                    fixer,
                )

                assert fixer(bucket_name_us, AWS_REGION_US_EAST_1)

    @mock_aws
    def test_bucket_public_write_ACL_AuthenticatedUsers_WRITE(self):
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)
        bucket_owner = s3_client.get_bucket_acl(Bucket=bucket_name_us)["Owner"]
        # Generate S3Control Client
        s3control_client = client("s3control", region_name=AWS_REGION_US_EAST_1)
        s3control_client.put_public_access_block(
            AccountId=AWS_ACCOUNT_NUMBER,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        s3_client.put_public_access_block(
            Bucket=bucket_name_us,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        s3_client.put_bucket_acl(
            Bucket=bucket_name_us,
            AccessControlPolicy={
                "Grants": [
                    {
                        "Grantee": {
                            "URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                            "Type": "Group",
                        },
                        "Permission": "WRITE",
                    },
                ],
                "Owner": bucket_owner,
            },
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl_fixer.s3_client",
                new=S3(aws_provider),
            ):
                # Test Fixer
                from prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl_fixer import (
                    fixer,
                )

                assert fixer(bucket_name_us, AWS_REGION_US_EAST_1)

    @mock_aws
    def test_bucket_public_write_ACL_AuthenticatedUsers_WRITE_ACP(self):
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)
        bucket_owner = s3_client.get_bucket_acl(Bucket=bucket_name_us)["Owner"]
        # Generate S3Control Client
        s3control_client = client("s3control", region_name=AWS_REGION_US_EAST_1)
        s3control_client.put_public_access_block(
            AccountId=AWS_ACCOUNT_NUMBER,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        s3_client.put_public_access_block(
            Bucket=bucket_name_us,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        s3_client.put_bucket_acl(
            Bucket=bucket_name_us,
            AccessControlPolicy={
                "Grants": [
                    {
                        "Grantee": {
                            "URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                            "Type": "Group",
                        },
                        "Permission": "WRITE_ACP",
                    },
                ],
                "Owner": bucket_owner,
            },
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl_fixer.s3_client",
                new=S3(aws_provider),
            ):
                # Test Fixer
                from prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl_fixer import (
                    fixer,
                )

                assert fixer(bucket_name_us, AWS_REGION_US_EAST_1)

    @mock_aws
    def test_bucket_public_write_ACL_AuthenticatedUsers_FULL_CONTROL(self):
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)
        bucket_owner = s3_client.get_bucket_acl(Bucket=bucket_name_us)["Owner"]
        # Generate S3Control Client
        s3control_client = client("s3control", region_name=AWS_REGION_US_EAST_1)
        s3control_client.put_public_access_block(
            AccountId=AWS_ACCOUNT_NUMBER,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        s3_client.put_public_access_block(
            Bucket=bucket_name_us,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        s3_client.put_bucket_acl(
            Bucket=bucket_name_us,
            AccessControlPolicy={
                "Grants": [
                    {
                        "Grantee": {
                            "URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                            "Type": "Group",
                        },
                        "Permission": "FULL_CONTROL",
                    },
                ],
                "Owner": bucket_owner,
            },
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl_fixer.s3_client",
                new=S3(aws_provider),
            ):
                # Test Fixer
                from prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl_fixer import (
                    fixer,
                )

                assert fixer(bucket_name_us, AWS_REGION_US_EAST_1)

    @mock_aws
    def test_bucket_public_write_ACL_AllUsers_WRITE_error(self):
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)
        bucket_owner = s3_client.get_bucket_acl(Bucket=bucket_name_us)["Owner"]
        # Generate S3Control Client
        s3control_client = client("s3control", region_name=AWS_REGION_US_EAST_1)
        s3control_client.put_public_access_block(
            AccountId=AWS_ACCOUNT_NUMBER,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        s3_client.put_public_access_block(
            Bucket=bucket_name_us,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        s3_client.put_bucket_acl(
            Bucket=bucket_name_us,
            AccessControlPolicy={
                "Grants": [
                    {
                        "Grantee": {
                            "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                            "Type": "Group",
                        },
                        "Permission": "WRITE",
                    },
                ],
                "Owner": bucket_owner,
            },
        )
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl_fixer.s3_client",
                new=S3(aws_provider),
            ):
                # Test Fixer
                from prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl_fixer import (
                    fixer,
                )

                assert not fixer("bucket_name_us_non_existing", AWS_REGION_US_EAST_1)
