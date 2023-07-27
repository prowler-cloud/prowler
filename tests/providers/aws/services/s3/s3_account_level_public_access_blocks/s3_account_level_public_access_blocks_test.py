from unittest import mock

from boto3 import client, session
from moto import mock_s3, mock_s3control

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
AWS_REGION = "us-east-1"


class Test_s3_account_level_public_access_blocks:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
                region_name=AWS_REGION,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=AWS_ACCOUNT_ARN,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=AWS_REGION,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
        )
        return audit_info

    @mock_s3
    @mock_s3control
    def test_bucket_account_public_block(self):
        # Generate S3Control Client
        s3control_client = client("s3control", region_name=AWS_REGION)
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

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_account_level_public_access_blocks.s3_account_level_public_access_blocks.s3_client",
                new=S3(audit_info),
            ):
                with mock.patch(
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
                    assert result[0].region == AWS_REGION

    @mock_s3
    @mock_s3control
    def test_bucket_without_account_public_block(self):
        # Generate S3Control Client
        s3control_client = client("s3control", region_name=AWS_REGION)
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

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_account_level_public_access_blocks.s3_account_level_public_access_blocks.s3_client",
                new=S3(audit_info),
            ):
                with mock.patch(
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
                    assert result[0].region == AWS_REGION
