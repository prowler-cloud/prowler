import json

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.s3.s3_service import S3, S3Control
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_S3_Service:

    # Test S3 Service
    @mock_aws
    def test_service(self):
        # S3 client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        s3 = S3(audit_info)
        assert s3.service == "s3"

    # Test S3 Client
    @mock_aws
    def test_client(self):
        # S3 client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        s3 = S3(audit_info)
        assert s3.client.__class__.__name__ == "S3"

    # Test S3 Session
    @mock_aws
    def test__get_session__(self):
        # S3 client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        s3 = S3(audit_info)
        assert s3.session.__class__.__name__ == "Session"

    # Test S3 Session
    @mock_aws
    def test_audited_account(self):
        # S3 client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        s3 = S3(audit_info)
        assert s3.audited_account == AWS_ACCOUNT_NUMBER

    # Test S3 List Buckets
    @mock_aws
    def test__list_buckets__(self):
        # Generate S3 Client
        s3_client = client("s3")
        # Create S3 Bucket
        bucket_name = "test-bucket"
        s3_client.create_bucket(Bucket=bucket_name)

        # S3 client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        s3 = S3(audit_info)

        assert len(s3.buckets) == 1
        assert s3.buckets[0].name == bucket_name
        assert (
            s3.buckets[0].arn
            == f"arn:{audit_info.audited_partition}:s3:::{bucket_name}"
        )
        assert not s3.buckets[0].object_lock

    # Test S3 Get Bucket Versioning
    @mock_aws
    def test__get_bucket_versioning__(self):
        # Generate S3 Client
        s3_client = client("s3")
        # Create S3 Bucket
        bucket_name = "test-bucket"
        s3_client.create_bucket(Bucket=bucket_name)
        # Set Bucket Versioning
        s3_client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={"MFADelete": "Disabled", "Status": "Enabled"},
        )
        # S3 client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        s3 = S3(audit_info)
        assert len(s3.buckets) == 1
        assert s3.buckets[0].name == bucket_name
        assert (
            s3.buckets[0].arn
            == f"arn:{audit_info.audited_partition}:s3:::{bucket_name}"
        )
        assert s3.buckets[0].versioning is True

    # Test S3 Get Bucket ACL
    @mock_aws
    def test__get_bucket_acl__(self):
        s3_client = client("s3")
        bucket_name = "test-bucket"
        s3_client.create_bucket(Bucket=bucket_name)
        s3_client.put_bucket_acl(
            AccessControlPolicy={
                "Grants": [
                    {
                        "Grantee": {
                            "DisplayName": "test",
                            "ID": "test_ID",
                            "Type": "Group",
                            "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                        },
                        "Permission": "READ",
                    },
                ],
                "Owner": {"DisplayName": "test", "ID": "test_id"},
            },
            Bucket=bucket_name,
        )
        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        s3 = S3(audit_info)
        assert len(s3.buckets) == 1
        assert s3.buckets[0].name == bucket_name
        assert (
            s3.buckets[0].arn
            == f"arn:{audit_info.audited_partition}:s3:::{bucket_name}"
        )
        assert s3.buckets[0].acl_grantees[0].display_name == "test"
        assert s3.buckets[0].acl_grantees[0].ID == "test_ID"
        assert s3.buckets[0].acl_grantees[0].type == "Group"
        assert (
            s3.buckets[0].acl_grantees[0].URI
            == "http://acs.amazonaws.com/groups/global/AllUsers"
        )

    # Test S3 Get Bucket Logging
    @mock_aws
    def test__get_bucket_logging__(self):
        # Generate S3 Client
        s3_client = client("s3")
        # Create S3 Bucket
        bucket_name = "test-bucket"
        s3_client.create_bucket(
            Bucket=bucket_name,
        )
        bucket_owner = s3_client.get_bucket_acl(Bucket=bucket_name)["Owner"]
        s3_client.put_bucket_acl(
            Bucket=bucket_name,
            AccessControlPolicy={
                "Grants": [
                    {
                        "Grantee": {
                            "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery",
                            "Type": "Group",
                        },
                        "Permission": "WRITE",
                    },
                    {
                        "Grantee": {
                            "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery",
                            "Type": "Group",
                        },
                        "Permission": "READ_ACP",
                    },
                    {
                        "Grantee": {"Type": "CanonicalUser", "ID": bucket_owner["ID"]},
                        "Permission": "FULL_CONTROL",
                    },
                ],
                "Owner": bucket_owner,
            },
        )

        s3_client.put_bucket_logging(
            Bucket=bucket_name,
            BucketLoggingStatus={
                "LoggingEnabled": {
                    "TargetBucket": bucket_name,
                    "TargetPrefix": "{}/".format(bucket_name),
                    "TargetGrants": [
                        {
                            "Grantee": {
                                "ID": "SOMEIDSTRINGHERE9238748923734823917498237489237409123840983274",
                                "Type": "CanonicalUser",
                            },
                            "Permission": "READ",
                        },
                        {
                            "Grantee": {
                                "ID": "SOMEIDSTRINGHERE9238748923734823917498237489237409123840983274",
                                "Type": "CanonicalUser",
                            },
                            "Permission": "WRITE",
                        },
                    ],
                }
            },
        )
        # S3 client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        s3 = S3(audit_info)
        assert len(s3.buckets) == 1
        assert s3.buckets[0].name == bucket_name
        assert (
            s3.buckets[0].arn
            == f"arn:{audit_info.audited_partition}:s3:::{bucket_name}"
        )
        assert s3.buckets[0].logging is True

    # Test S3 Get Bucket Policy
    @mock_aws
    def test__get_bucket_policy__(self):
        s3_client = client("s3")
        bucket_name = "test-bucket"
        s3_client.create_bucket(Bucket=bucket_name)
        ssl_policy = '{"Version": "2012-10-17","Id": "PutObjPolicy","Statement": [{"Sid": "s3-bucket-ssl-requests-only","Effect": "Deny","Principal": "*","Action": "s3:GetObject","Resource": "arn:aws:s3:::bucket_test_us/*","Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}'
        s3_client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=ssl_policy,
        )
        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        s3 = S3(audit_info)
        assert len(s3.buckets) == 1
        assert s3.buckets[0].name == bucket_name
        assert (
            s3.buckets[0].arn
            == f"arn:{audit_info.audited_partition}:s3:::{bucket_name}"
        )
        assert s3.buckets[0].policy == json.loads(ssl_policy)

    # Test S3 Get Bucket Encryption
    @mock_aws
    def test__get_bucket_encryption__(self):
        # Generate S3 Client
        s3_client = client("s3")
        # Create S3 Bucket
        bucket_name = "test-bucket"
        s3_client.create_bucket(Bucket=bucket_name)
        sse_config = {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                        "KMSMasterKeyID": "12345678",
                    }
                }
            ]
        }

        s3_client.put_bucket_encryption(
            Bucket=bucket_name, ServerSideEncryptionConfiguration=sse_config
        )
        # S3 client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        s3 = S3(audit_info)
        assert len(s3.buckets) == 1
        assert s3.buckets[0].name == bucket_name
        assert (
            s3.buckets[0].arn
            == f"arn:{audit_info.audited_partition}:s3:::{bucket_name}"
        )
        assert s3.buckets[0].encryption == "aws:kms"

    # Test S3 Get Bucket Ownership Controls
    @mock_aws
    def test__get_bucket_ownership_controls__(self):
        # Generate S3 Client
        s3_client = client("s3")
        # Create S3 Bucket
        bucket_name = "test-bucket"
        s3_client.create_bucket(
            Bucket=bucket_name, ObjectOwnership="BucketOwnerEnforced"
        )

        # S3 client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        s3 = S3(audit_info)
        assert len(s3.buckets) == 1
        assert s3.buckets[0].name == bucket_name
        assert (
            s3.buckets[0].arn
            == f"arn:{audit_info.audited_partition}:s3:::{bucket_name}"
        )
        assert s3.buckets[0].ownership == "BucketOwnerEnforced"

    # Test S3 Get Public Access Block
    @mock_aws
    def test__get_public_access_block__(self):
        # Generate S3 Client
        s3_client = client("s3")
        # Create S3 Bucket
        bucket_name = "test-bucket"
        s3_client.create_bucket(
            Bucket=bucket_name, ObjectOwnership="BucketOwnerEnforced"
        )
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        # S3 client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        s3 = S3(audit_info)
        assert len(s3.buckets) == 1
        assert s3.buckets[0].name == bucket_name
        assert (
            s3.buckets[0].arn
            == f"arn:{audit_info.audited_partition}:s3:::{bucket_name}"
        )
        assert s3.buckets[0].public_access_block.block_public_acls
        assert s3.buckets[0].public_access_block.ignore_public_acls
        assert s3.buckets[0].public_access_block.block_public_policy
        assert s3.buckets[0].public_access_block.restrict_public_buckets

    # Test S3 Get Bucket Tagging
    @mock_aws
    def test__get_bucket_tagging__(self):
        # Generate S3 Client
        s3_client = client("s3")
        # Create S3 Bucket
        bucket_name = "test-bucket"
        s3_client.create_bucket(Bucket=bucket_name)
        s3_client.put_bucket_tagging(
            Bucket=bucket_name,
            Tagging={
                "TagSet": [
                    {"Key": "test", "Value": "test"},
                ]
            },
        )
        # S3 client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        s3 = S3(audit_info)

        assert len(s3.buckets) == 1
        assert s3.buckets[0].tags == [
            {"Key": "test", "Value": "test"},
        ]

    # Test S3 Control Account Get Public Access Block
    @mock_aws
    def test__get_public_access_block__s3_control(self):
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
        # S3 client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        s3control = S3Control(audit_info)
        assert s3control.account_public_access_block.block_public_acls
        assert s3control.account_public_access_block.ignore_public_acls
        assert s3control.account_public_access_block.block_public_policy
        assert s3control.account_public_access_block.restrict_public_buckets

    # Test S3 Get Bucket Object Lock
    @mock_aws
    def test__get_object_lock_configuration__(self):
        # Generate S3 Client
        s3_client = client("s3")
        # Create S3 Bucket
        bucket_name = "test-bucket"
        s3_client.create_bucket(
            Bucket=bucket_name,
            ObjectOwnership="BucketOwnerEnforced",
            ObjectLockEnabledForBucket=True,
        )

        # S3 client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        s3 = S3(audit_info)
        assert len(s3.buckets) == 1
        assert s3.buckets[0].name == bucket_name
        assert (
            s3.buckets[0].arn
            == f"arn:{audit_info.audited_partition}:s3:::{bucket_name}"
        )
        assert s3.buckets[0].object_lock
