from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_s3_bucket_public_list_acl:
    @mock_aws
    def test_no_buckets(self):
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl.s3_client",
                new=S3(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl.s3control_client",
                    new=S3Control(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl import (
                        s3_bucket_public_list_acl,
                    )

                    check = s3_bucket_public_list_acl()
                    result = check.execute()

                    assert len(result) == 0

    @mock_aws
    def test_bucket_account_public_block_without_buckets(self):
        # Generate S3Control Client
        s3control_client = client("s3control", region_name=AWS_REGION_US_EAST_1)
        s3control_client.put_public_access_block(
            AccountId=AWS_ACCOUNT_NUMBER,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl.s3_client",
                new=S3(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl.s3control_client",
                    new=S3Control(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl import (
                        s3_bucket_public_list_acl,
                    )

                    check = s3_bucket_public_list_acl()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert (
                        result[0].status_extended
                        == "All S3 public access blocked at account level."
                    )
                    assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                    assert (
                        result[0].resource_arn
                        == f"arn:aws:s3:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:account"
                    )
                    assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_account_public_block(self):
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)
        # Generate S3Control Client
        s3control_client = client("s3control", region_name=AWS_REGION_US_EAST_1)
        s3control_client.put_public_access_block(
            AccountId=AWS_ACCOUNT_NUMBER,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl.s3_client",
                new=S3(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl.s3control_client",
                    new=S3Control(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl import (
                        s3_bucket_public_list_acl,
                    )

                    check = s3_bucket_public_list_acl()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert (
                        result[0].status_extended
                        == "All S3 public access blocked at account level."
                    )
                    assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                    assert (
                        result[0].resource_arn
                        == f"arn:aws:s3:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:account"
                    )
                    assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_public_block(self):
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)
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
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl.s3_client",
                new=S3(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl.s3control_client",
                    new=S3Control(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl import (
                        s3_bucket_public_list_acl,
                    )

                    check = s3_bucket_public_list_acl()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert (
                        result[0].status_extended
                        == f"S3 Bucket {bucket_name_us} is not publicly listable."
                    )
                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_public_list_ACL_AllUsers_READ(self):
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
                        "Permission": "READ",
                    },
                ],
                "Owner": bucket_owner,
            },
        )
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl.s3_client",
                new=S3(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl.s3control_client",
                    new=S3Control(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl import (
                        s3_bucket_public_list_acl,
                    )

                    check = s3_bucket_public_list_acl()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "FAIL"
                    assert (
                        result[0].status_extended
                        == f"S3 Bucket {bucket_name_us} is listable by anyone due to the bucket ACL: AllUsers having the READ permission."
                    )

                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_public_list_ACL_AllUsers_READ_ACP(self):
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
                        "Permission": "READ_ACP",
                    },
                ],
                "Owner": bucket_owner,
            },
        )
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl.s3_client",
                new=S3(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl.s3control_client",
                    new=S3Control(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl import (
                        s3_bucket_public_list_acl,
                    )

                    check = s3_bucket_public_list_acl()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "FAIL"
                    assert (
                        result[0].status_extended
                        == f"S3 Bucket {bucket_name_us} is listable by anyone due to the bucket ACL: AllUsers having the READ_ACP permission."
                    )

                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_public_list_ACL_AllUsers_FULL_CONTROL(self):
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
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl.s3_client",
                new=S3(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl.s3control_client",
                    new=S3Control(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl import (
                        s3_bucket_public_list_acl,
                    )

                    check = s3_bucket_public_list_acl()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "FAIL"
                    assert (
                        result[0].status_extended
                        == f"S3 Bucket {bucket_name_us} is listable by anyone due to the bucket ACL: AllUsers having the FULL_CONTROL permission."
                    )

                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_public_list_ACL_AuthenticatedUsers_READ(self):
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
                        "Permission": "READ",
                    },
                ],
                "Owner": bucket_owner,
            },
        )
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl.s3_client",
                new=S3(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl.s3control_client",
                    new=S3Control(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl import (
                        s3_bucket_public_list_acl,
                    )

                    check = s3_bucket_public_list_acl()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "FAIL"
                    assert (
                        result[0].status_extended
                        == f"S3 Bucket {bucket_name_us} is listable by anyone due to the bucket ACL: AuthenticatedUsers having the READ permission."
                    )

                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_public_list_ACL_AuthenticatedUsers_READ_ACP(self):
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
                        "Permission": "READ_ACP",
                    },
                ],
                "Owner": bucket_owner,
            },
        )
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl.s3_client",
                new=S3(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl.s3control_client",
                    new=S3Control(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl import (
                        s3_bucket_public_list_acl,
                    )

                    check = s3_bucket_public_list_acl()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "FAIL"
                    assert (
                        result[0].status_extended
                        == f"S3 Bucket {bucket_name_us} is listable by anyone due to the bucket ACL: AuthenticatedUsers having the READ_ACP permission."
                    )

                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_public_list_ACL_AuthenticatedUsers_FULL_CONTROL(self):
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
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl.s3_client",
                new=S3(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl.s3control_client",
                    new=S3Control(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_list_acl.s3_bucket_public_list_acl import (
                        s3_bucket_public_list_acl,
                    )

                    check = s3_bucket_public_list_acl()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "FAIL"
                    assert (
                        result[0].status_extended
                        == f"S3 Bucket {bucket_name_us} is listable by anyone due to the bucket ACL: AuthenticatedUsers having the FULL_CONTROL permission."
                    )

                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION_US_EAST_1
