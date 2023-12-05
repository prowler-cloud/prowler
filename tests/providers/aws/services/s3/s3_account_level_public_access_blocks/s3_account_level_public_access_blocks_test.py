from unittest import mock

from boto3 import client
from moto import mock_s3, mock_s3control

from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_ARN,
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_s3_account_level_public_access_blocks:
    @mock_s3
    @mock_s3control
    def test_bucket_account_public_block(self):
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

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_account_level_public_access_blocks.s3_account_level_public_access_blocks.s3_client",
            new=S3(audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_account_level_public_access_blocks.s3_account_level_public_access_blocks.s3control_client",
            new=S3Control(audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_account_level_public_access_blocks.s3_account_level_public_access_blocks import (
                s3_account_level_public_access_blocks,
            )

            check = s3_account_level_public_access_blocks()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Block Public Access is configured for the account {AWS_ACCOUNT_NUMBER}."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == AWS_ACCOUNT_ARN
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_s3
    @mock_s3control
    def test_bucket_without_account_public_block(self):
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
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_account_level_public_access_blocks.s3_account_level_public_access_blocks.s3_client",
            new=S3(audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_account_level_public_access_blocks.s3_account_level_public_access_blocks.s3control_client",
            new=S3Control(audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_account_level_public_access_blocks.s3_account_level_public_access_blocks import (
                s3_account_level_public_access_blocks,
            )

            check = s3_account_level_public_access_blocks()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Block Public Access is not configured for the account {AWS_ACCOUNT_NUMBER}."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == AWS_ACCOUNT_ARN
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_s3
    @mock_s3control
    def test_bucket_without_account_public_block_ignoring(self):
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
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        audit_info.ignore_unused_services = True

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_account_level_public_access_blocks.s3_account_level_public_access_blocks.s3_client",
            new=S3(audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.s3.s3_account_level_public_access_blocks.s3_account_level_public_access_blocks.s3control_client",
            new=S3Control(audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.s3.s3_account_level_public_access_blocks.s3_account_level_public_access_blocks import (
                s3_account_level_public_access_blocks,
            )

            check = s3_account_level_public_access_blocks()
            result = check.execute()

            assert len(result) == 0
