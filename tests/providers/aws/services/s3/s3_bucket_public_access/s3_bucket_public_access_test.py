from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_s3_bucket_public_access:
    @mock_aws
    def test_no_buckets(self):
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3_client",
                new=S3(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3control_client",
                    new=S3Control(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access import (
                        s3_bucket_public_access,
                    )

                    check = s3_bucket_public_access()
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
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3_client",
                new=S3(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3control_client",
                    new=S3Control(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access import (
                        s3_bucket_public_access,
                    )

                    check = s3_bucket_public_access()
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
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3_client",
                new=S3(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3control_client",
                    new=S3Control(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access import (
                        s3_bucket_public_access,
                    )

                    check = s3_bucket_public_access()
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
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3_client",
                new=S3(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3control_client",
                    new=S3Control(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access import (
                        s3_bucket_public_access,
                    )

                    check = s3_bucket_public_access()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert (
                        result[0].status_extended
                        == f"S3 Bucket {bucket_name_us} is not public."
                    )
                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_public_ACL(self):
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
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3_client",
                new=S3(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3control_client",
                    new=S3Control(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access import (
                        s3_bucket_public_access,
                    )

                    check = s3_bucket_public_access()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "FAIL"
                    assert (
                        result[0].status_extended
                        == f"S3 Bucket {bucket_name_us} has public access due to bucket ACL."
                    )
                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_public_policy(self):
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
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        public_write_policy = '{"Version": "2012-10-17","Id": "PutObjPolicy","Statement": [{"Sid": "PublicWritePolicy","Effect": "Allow","Principal": "*","Action": "s3:PutObject","Resource": "arn:aws:s3:::bucket_test_us/*"}]}'
        s3_client.put_bucket_policy(
            Bucket=bucket_name_us,
            Policy=public_write_policy,
        )
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3_client",
                new=S3(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3control_client",
                    new=S3Control(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access import (
                        s3_bucket_public_access,
                    )

                    check = s3_bucket_public_access()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "FAIL"
                    assert (
                        result[0].status_extended
                        == f"S3 Bucket {bucket_name_us} has public access due to bucket policy."
                    )
                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_not_public_due_to_policy_conditions_from_vpc(self):
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
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        public_write_policy = '{"Version": "2012-10-17","Id": "PutObjPolicy","Statement": [{"Sid": "PublicWritePolicy","Effect": "Allow","Principal": "*","Action": "s3:PutObject","Resource": "arn:aws:s3:::bucket_test_us/*","Condition": {"StringEquals": {"aws:SourceVpc": "vpc-123456"}}}]}'
        s3_client.put_bucket_policy(
            Bucket=bucket_name_us,
            Policy=public_write_policy,
        )
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3_client",
                new=S3(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3control_client",
                    new=S3Control(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access import (
                        s3_bucket_public_access,
                    )

                    check = s3_bucket_public_access()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert (
                        result[0].status_extended
                        == f"S3 Bucket {bucket_name_us} is not public."
                    )
                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_not_public_due_to_policy_conditions_from_private_ip(self):
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
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        public_write_policy = '{"Version": "2012-10-17","Id": "PutObjPolicy","Statement": [{"Sid": "PublicWritePolicy","Effect": "Allow","Principal": "*","Action": "s3:PutObject","Resource": "arn:aws:s3:::bucket_test_us/*","Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.25"}}}]}'
        s3_client.put_bucket_policy(
            Bucket=bucket_name_us,
            Policy=public_write_policy,
        )
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3_client",
            new=S3(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3control_client",
            new=S3Control(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access import (
                s3_bucket_public_access,
            )

            check = s3_bucket_public_access()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"S3 Bucket {bucket_name_us} is not public."
            )
            assert result[0].resource_id == bucket_name_us
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_public_due_to_policy_conditions_from_public_ip(self):
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
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        public_write_policy = '{"Version": "2012-10-17","Id": "PutObjPolicy","Statement": [{"Sid": "PublicWritePolicy","Effect": "Allow","Principal": "*","Action": "s3:PutObject","Resource": "arn:aws:s3:::bucket_test_us/*","Condition": {"IpAddress": {"aws:SourceIp": "1.2.3.4"}}}]}'
        s3_client.put_bucket_policy(
            Bucket=bucket_name_us,
            Policy=public_write_policy,
        )
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3_client",
            new=S3(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3control_client",
            new=S3Control(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access import (
                s3_bucket_public_access,
            )

            check = s3_bucket_public_access()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"S3 Bucket {bucket_name_us} has public access due to bucket policy."
            )
            assert result[0].resource_id == bucket_name_us
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_public_due_to_policy_conditions_from_public_and_private_ips(self):
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
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        public_write_policy = '{"Version": "2012-10-17","Id": "PutObjPolicy","Statement": [{"Sid": "PublicWritePolicy","Effect": "Allow","Principal": "*","Action": "s3:PutObject","Resource": "arn:aws:s3:::bucket_test_us/*","Condition": {"IpAddress": {"aws:SourceIp": ["192.168.10.0/24", "2001:DB8:1234:5678::/64", "1.2.3.4"]}}}]}'
        s3_client.put_bucket_policy(
            Bucket=bucket_name_us,
            Policy=public_write_policy,
        )
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3_client",
            new=S3(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3control_client",
            new=S3Control(aws_provider),
        ):
            from prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access import (
                s3_bucket_public_access,
            )

            check = s3_bucket_public_access()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"S3 Bucket {bucket_name_us} has public access due to bucket policy."
            )
            assert result[0].resource_id == bucket_name_us
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_not_public(self):
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)
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
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3_client",
                new=S3(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3control_client",
                    new=S3Control(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access import (
                        s3_bucket_public_access,
                    )

                    check = s3_bucket_public_access()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert (
                        result[0].status_extended
                        == f"S3 Bucket {bucket_name_us} is not public."
                    )
                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_can_not_retrieve_public_access_block(self):
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        bucket_arn = f"arn:aws:s3:::{bucket_name_us}"
        s3_client.create_bucket(Bucket=bucket_name_us)
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
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            # To test this behaviour we need to set public_access_block to None
            s3 = S3(aws_provider)
            s3.buckets[bucket_arn].public_access_block = None
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3_client",
                new=s3,
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3control_client",
                    new=S3Control(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access import (
                        s3_bucket_public_access,
                    )

                    check = s3_bucket_public_access()
                    result = check.execute()

                    assert len(result) == 0

    @mock_aws
    def test_bucket_public_with_aws_principals(self):
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
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        public_write_policy = '{"Version": "2012-10-17","Id": "PutObjPolicy","Statement": [{"Sid": "PublicWritePolicy","Effect": "Allow","Principal": {"AWS": ["arn:aws:iam::123456789012:root", "*"]},"Action": "s3:PutObject","Resource": "arn:aws:s3:::bucket_test_us/*"}]}'
        s3_client.put_bucket_policy(
            Bucket=bucket_name_us,
            Policy=public_write_policy,
        )
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3_client",
                new=S3(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3control_client",
                    new=S3Control(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access import (
                        s3_bucket_public_access,
                    )

                    check = s3_bucket_public_access()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "FAIL"
                    assert (
                        result[0].status_extended
                        == f"S3 Bucket {bucket_name_us} has public access due to bucket policy."
                    )
                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION_US_EAST_1
