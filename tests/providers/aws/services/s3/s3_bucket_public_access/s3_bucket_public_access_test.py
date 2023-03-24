from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_s3, mock_s3control

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.s3.s3_service import Bucket

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


class Test_s3_bucket_public_access:
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
        )
        return audit_info

    @mock_s3
    @mock_s3control
    def test_no_buckets(self):
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3_client",
                new=S3(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3control_client",
                    new=S3Control(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access import (
                        s3_bucket_public_access,
                    )

                    check = s3_bucket_public_access()
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

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3_client",
                new=S3(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3control_client",
                    new=S3Control(audit_info),
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

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3_client",
                new=S3(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3control_client",
                    new=S3Control(audit_info),
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

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3_client",
                new=S3(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3control_client",
                    new=S3Control(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access import (
                        s3_bucket_public_access,
                    )

                    check = s3_bucket_public_access()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert search(
                        "not public",
                        result[0].status_extended,
                    )
                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{audit_info.audited_partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION

    @mock_s3
    @mock_s3control
    def test_bucket_public_ACL(self):
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
                        "Permission": "READ",
                    },
                ],
                "Owner": bucket_owner,
            },
        )
        from prowler.providers.aws.services.s3.s3_service import S3, S3Control

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3_client",
                new=S3(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3control_client",
                    new=S3Control(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access import (
                        s3_bucket_public_access,
                    )

                    check = s3_bucket_public_access()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "FAIL"
                    assert search(
                        "public access due to bucket ACL",
                        result[0].status_extended,
                    )
                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{audit_info.audited_partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION

    @mock_s3
    @mock_s3control
    def test_bucket_public_policy(self):
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

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3_client",
                new=S3(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3control_client",
                    new=S3Control(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access import (
                        s3_bucket_public_access,
                    )

                    check = s3_bucket_public_access()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "FAIL"
                    assert search(
                        "public access due to bucket policy",
                        result[0].status_extended,
                    )
                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{audit_info.audited_partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION

    @mock_s3
    @mock_s3control
    def test_bucket_not_public(self):
        s3_client = client("s3", region_name=AWS_REGION)
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

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3_client",
                new=S3(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access.s3control_client",
                    new=S3Control(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access import (
                        s3_bucket_public_access,
                    )

                    check = s3_bucket_public_access()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert search(
                        "not public",
                        result[0].status_extended,
                    )
                    assert result[0].resource_id == bucket_name_us
                    assert (
                        result[0].resource_arn
                        == f"arn:{audit_info.audited_partition}:s3:::{bucket_name_us}"
                    )
                    assert result[0].region == AWS_REGION

    def test_bucket_can_not_retrieve_public_access_block(self):
        s3_client = mock.MagicMock
        s3_client.buckets = [
            Bucket(
                name="test-bucket",
                arn="",
                public_access_block=None,
                encryption=None,
                region=AWS_REGION,
                logging_target_bucket=None,
                ownership=None,
            )
        ]

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_service.S3",
                new=s3_client,
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_public_access.s3_bucket_public_access import (
                    s3_bucket_public_access,
                )

                check = s3_bucket_public_access()
                result = check.execute()

                assert len(result) == 0
