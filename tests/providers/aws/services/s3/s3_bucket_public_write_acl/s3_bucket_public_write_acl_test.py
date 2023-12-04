from unittest import mock

from boto3 import client, session
from moto import mock_s3, mock_s3control

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
AWS_REGION = "us-east-1"


class Test_s3_bucket_public_write_acl:
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
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )
        return audit_info

    @mock_s3
    @mock_s3control
    def test_no_buckets(self):
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl.s3_client",
                new=S3(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl.s3control_client",
                    new=S3Control(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl import (
                        s3_bucket_public_write_acl,
                    )

                    check = s3_bucket_public_write_acl()
                    result = check.execute()

                    assert len(result) == 0

    @mock_s3
    @mock_s3control
    def test_bucket_account_public_block_without_buckets(self):
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

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl.s3_client",
                new=S3(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl.s3control_client",
                    new=S3Control(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl import (
                        s3_bucket_public_write_acl,
                    )

                    check = s3_bucket_public_write_acl()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert (
                        result[0].status_extended
                        == "All S3 public access blocked at account level."
                    )
                    assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                    assert result[0].resource_arn == AWS_ACCOUNT_ARN
                    assert result[0].region == AWS_REGION

    @mock_s3
    @mock_s3control
    def test_bucket_account_public_block(self):
        s3_client = client("s3", region_name=AWS_REGION)
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)
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

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl.s3_client",
                new=S3(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl.s3control_client",
                    new=S3Control(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl import (
                        s3_bucket_public_write_acl,
                    )

                    check = s3_bucket_public_write_acl()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert (
                        result[0].status_extended
                        == "All S3 public access blocked at account level."
                    )
                    assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                    assert result[0].resource_arn == AWS_ACCOUNT_ARN
                    assert result[0].region == AWS_REGION

    @mock_s3
    @mock_s3control
    def test_bucket_public_block(self):
        s3_client = client("s3", region_name=AWS_REGION)
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)
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

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl.s3_client",
                new=S3(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl.s3control_client",
                    new=S3Control(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl import (
                        s3_bucket_public_write_acl,
                    )

                    check = s3_bucket_public_write_acl()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert (
                        result[0].status_extended
                        == f"S3 Bucket {bucket_name_us} is not publicly writable."
                    )
                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{audit_info.audited_partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION

    @mock_s3
    @mock_s3control
    def test_bucket_public_write_ACL_AllUsers_WRITE(self):
        s3_client = client("s3", region_name=AWS_REGION)
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)
        bucket_owner = s3_client.get_bucket_acl(Bucket=bucket_name_us)["Owner"]
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
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl.s3_client",
                new=S3(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl.s3control_client",
                    new=S3Control(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl import (
                        s3_bucket_public_write_acl,
                    )

                    check = s3_bucket_public_write_acl()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "FAIL"
                    assert (
                        result[0].status_extended
                        == f"S3 Bucket {bucket_name_us} is writable by anyone due to the bucket ACL: AllUsers having the WRITE permission."
                    )

                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{audit_info.audited_partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION

    @mock_s3
    @mock_s3control
    def test_bucket_public_write_ACL_AllUsers_WRITE_ACP(self):
        s3_client = client("s3", region_name=AWS_REGION)
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)
        bucket_owner = s3_client.get_bucket_acl(Bucket=bucket_name_us)["Owner"]
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
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl.s3_client",
                new=S3(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl.s3control_client",
                    new=S3Control(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl import (
                        s3_bucket_public_write_acl,
                    )

                    check = s3_bucket_public_write_acl()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "FAIL"
                    assert (
                        result[0].status_extended
                        == f"S3 Bucket {bucket_name_us} is writable by anyone due to the bucket ACL: AllUsers having the WRITE_ACP permission."
                    )

                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{audit_info.audited_partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION

    @mock_s3
    @mock_s3control
    def test_bucket_public_write_ACL_AllUsers_FULL_CONTROL(self):
        s3_client = client("s3", region_name=AWS_REGION)
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)
        bucket_owner = s3_client.get_bucket_acl(Bucket=bucket_name_us)["Owner"]
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

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl.s3_client",
                new=S3(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl.s3control_client",
                    new=S3Control(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl import (
                        s3_bucket_public_write_acl,
                    )

                    check = s3_bucket_public_write_acl()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "FAIL"
                    assert (
                        result[0].status_extended
                        == f"S3 Bucket {bucket_name_us} is writable by anyone due to the bucket ACL: AllUsers having the FULL_CONTROL permission."
                    )

                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{audit_info.audited_partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION

    @mock_s3
    @mock_s3control
    def test_bucket_public_write_ACL_AuthenticatedUsers_WRITE(self):
        s3_client = client("s3", region_name=AWS_REGION)
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)
        bucket_owner = s3_client.get_bucket_acl(Bucket=bucket_name_us)["Owner"]
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
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl.s3_client",
                new=S3(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl.s3control_client",
                    new=S3Control(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl import (
                        s3_bucket_public_write_acl,
                    )

                    check = s3_bucket_public_write_acl()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "FAIL"
                    assert (
                        result[0].status_extended
                        == f"S3 Bucket {bucket_name_us} is writable by anyone due to the bucket ACL: AuthenticatedUsers having the WRITE permission."
                    )

                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{audit_info.audited_partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION

    @mock_s3
    @mock_s3control
    def test_bucket_public_write_ACL_AuthenticatedUsers_WRITE_ACP(self):
        s3_client = client("s3", region_name=AWS_REGION)
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)
        bucket_owner = s3_client.get_bucket_acl(Bucket=bucket_name_us)["Owner"]
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
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl.s3_client",
                new=S3(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl.s3control_client",
                    new=S3Control(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl import (
                        s3_bucket_public_write_acl,
                    )

                    check = s3_bucket_public_write_acl()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "FAIL"
                    assert (
                        result[0].status_extended
                        == f"S3 Bucket {bucket_name_us} is writable by anyone due to the bucket ACL: AuthenticatedUsers having the WRITE_ACP permission."
                    )

                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{audit_info.audited_partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION

    @mock_s3
    @mock_s3control
    def test_bucket_public_write_ACL_AuthenticatedUsers_FULL_CONTROL(self):
        s3_client = client("s3", region_name=AWS_REGION)
        bucket_name_us = "bucket_test_us"
        s3_client.create_bucket(Bucket=bucket_name_us)
        bucket_owner = s3_client.get_bucket_acl(Bucket=bucket_name_us)["Owner"]
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

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl.s3_client",
                new=S3(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl.s3control_client",
                    new=S3Control(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_write_acl.s3_bucket_public_write_acl import (
                        s3_bucket_public_write_acl,
                    )

                    check = s3_bucket_public_write_acl()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "FAIL"
                    assert (
                        result[0].status_extended
                        == f"S3 Bucket {bucket_name_us} is writable by anyone due to the bucket ACL: AuthenticatedUsers having the FULL_CONTROL permission."
                    )

                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{audit_info.audited_partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION
