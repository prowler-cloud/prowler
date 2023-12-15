from unittest import mock

from boto3 import client
from moto import mock_s3, mock_s3control

from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_s3_bucket_level_public_access_block:
    @mock_s3
    @mock_s3control
    def test_no_buckets(self):
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_level_public_access_block.s3_bucket_level_public_access_block.s3_client",
                new=S3(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_level_public_access_block.s3_bucket_level_public_access_block.s3control_client",
                    new=S3Control(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_level_public_access_block.s3_bucket_level_public_access_block import (
                        s3_bucket_level_public_access_block,
                    )

                    check = s3_bucket_level_public_access_block()
                    result = check.execute()

                    assert len(result) == 0

    @mock_s3
    @mock_s3control
    def test_bucket_without_public_block(self):
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)
        s3_client.put_public_access_block(
            Bucket=bucket_name_us,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
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
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_level_public_access_block.s3_bucket_level_public_access_block.s3_client",
                new=S3(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_level_public_access_block.s3_bucket_level_public_access_block.s3control_client",
                    new=S3Control(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_level_public_access_block.s3_bucket_level_public_access_block import (
                        s3_bucket_level_public_access_block,
                    )

                    check = s3_bucket_level_public_access_block()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "FAIL"
                    assert (
                        result[0].status_extended
                        == f"Block Public Access is not configured for the S3 Bucket {bucket_name_us}."
                    )
                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{audit_info.audited_partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION_US_EAST_1

    @mock_s3
    @mock_s3control
    def test_bucket_public_block(self):
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
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_level_public_access_block.s3_bucket_level_public_access_block.s3_client",
                new=S3(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_level_public_access_block.s3_bucket_level_public_access_block.s3control_client",
                    new=S3Control(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_level_public_access_block.s3_bucket_level_public_access_block import (
                        s3_bucket_level_public_access_block,
                    )

                    check = s3_bucket_level_public_access_block()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert (
                        result[0].status_extended
                        == f"Block Public Access is configured for the S3 Bucket {bucket_name_us}."
                    )

                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{audit_info.audited_partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION_US_EAST_1

    @mock_s3
    @mock_s3control
    def test_bucket_public_block_at_account(self):
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)
        s3_client.put_public_access_block(
            Bucket=bucket_name_us,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
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

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_level_public_access_block.s3_bucket_level_public_access_block.s3_client",
                new=S3(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_level_public_access_block.s3_bucket_level_public_access_block.s3control_client",
                    new=S3Control(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_level_public_access_block.s3_bucket_level_public_access_block import (
                        s3_bucket_level_public_access_block,
                    )

                    check = s3_bucket_level_public_access_block()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert (
                        result[0].status_extended
                        == f"Block Public Access is configured for the S3 Bucket {bucket_name_us} at account {AWS_ACCOUNT_NUMBER} level."
                    )

                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{audit_info.audited_partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION_US_EAST_1

    @mock_s3
    @mock_s3control
    def test_bucket_can_not_retrieve_public_access_block(self):
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
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            # To test this behaviour we need to set public_access_block to None
            s3 = S3(audit_info)
            s3.buckets[0].public_access_block = None

            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_level_public_access_block.s3_bucket_level_public_access_block.s3_client",
                new=s3,
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_level_public_access_block.s3_bucket_level_public_access_block.s3control_client",
                    new=S3Control(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_level_public_access_block.s3_bucket_level_public_access_block import (
                        s3_bucket_level_public_access_block,
                    )

                    check = s3_bucket_level_public_access_block()
                    result = check.execute()

                    assert len(result) == 0
