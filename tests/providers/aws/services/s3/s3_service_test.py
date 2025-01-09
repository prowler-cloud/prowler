import json
from unittest.mock import patch

import botocore
import botocore.exceptions
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.s3.s3_service import S3, S3Control
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

# Original botocore _make_api_call function
orig = botocore.client.BaseClient._make_api_call


# Mocked botocore _make_api_call function
def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListAccessPoints":
        return {
            "AccessPointList": [
                {
                    "Name": "test-access-point",
                    "Bucket": "test-bucket",
                    "AccessPointArn": f"arn:aws:s3:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:accesspoint/test-access-point",
                }
            ]
        }
    if operation_name == "GetBucketLifecycleConfiguration":
        return {
            "Rules": [
                {
                    "ID": "test",
                    "Status": "Enabled",
                    "Prefix": "test",
                }
            ]
        }
    return orig(self, operation_name, kwarg)


class Test_S3_Service:
    # Test S3 Service
    @mock_aws
    def test_service(self):
        # S3 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        s3 = S3(aws_provider)
        assert s3.service == "s3"

    # Test S3 Client
    @mock_aws
    def test_client(self):
        # S3 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        s3 = S3(aws_provider)
        assert s3.client.__class__.__name__ == "S3"

    # Test S3 Session
    @mock_aws
    def test__get_session__(self):
        # S3 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        s3 = S3(aws_provider)
        assert s3.session.__class__.__name__ == "Session"

    # Test S3 Session
    @mock_aws
    def test_audited_account(self):
        # S3 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        s3 = S3(aws_provider)
        assert s3.audited_account == AWS_ACCOUNT_NUMBER

    # Test S3 List Buckets
    @mock_aws
    def test_list_buckets(self):
        # Generate S3 Client
        s3_client = client("s3")
        # Create S3 Bucket
        bucket_name = "test-bucket"
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
        s3_client.create_bucket(Bucket=bucket_name)

        # S3 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        s3 = S3(aws_provider)

        assert len(s3.buckets) == 1
        assert s3.buckets[bucket_arn].name == bucket_name
        assert s3.buckets[bucket_arn].region == AWS_REGION_US_EAST_1
        assert not s3.buckets[bucket_arn].object_lock

    # Test S3 Get Bucket Versioning
    @mock_aws
    def test_get_bucket_versioning(self):
        # Generate S3 Client
        s3_client = client("s3")
        # Create S3 Bucket
        bucket_name = "test-bucket"
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
        s3_client.create_bucket(Bucket=bucket_name)
        # Set Bucket Versioning
        s3_client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={"MFADelete": "Disabled", "Status": "Enabled"},
        )
        # S3 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        s3 = S3(aws_provider)
        assert len(s3.buckets) == 1
        assert s3.buckets[bucket_arn].name == bucket_name
        assert s3.buckets[bucket_arn].region == AWS_REGION_US_EAST_1
        assert s3.buckets[bucket_arn].versioning is True

    # Test S3 Get Bucket ACL
    @mock_aws
    def test_get_bucket_acl(self):
        s3_client = client("s3")
        bucket_name = "test-bucket"
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
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
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        s3 = S3(aws_provider)
        assert len(s3.buckets) == 1
        assert s3.buckets[bucket_arn].name == bucket_name
        assert s3.buckets[bucket_arn].region == AWS_REGION_US_EAST_1
        assert s3.buckets[bucket_arn].acl_grantees[0].display_name == "test"
        assert s3.buckets[bucket_arn].acl_grantees[0].ID == "test_ID"
        assert s3.buckets[bucket_arn].acl_grantees[0].type == "Group"
        assert (
            s3.buckets[bucket_arn].acl_grantees[0].URI
            == "http://acs.amazonaws.com/groups/global/AllUsers"
        )

    # Test S3 Get Bucket Logging
    @mock_aws
    def test_get_bucket_logging(self):
        # Generate S3 Client
        s3_client = client("s3")
        # Create S3 Bucket
        bucket_name = "test-bucket"
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
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
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        s3 = S3(aws_provider)
        assert len(s3.buckets) == 1
        assert s3.buckets[bucket_arn].name == bucket_name
        assert s3.buckets[bucket_arn].region == AWS_REGION_US_EAST_1
        assert s3.buckets[bucket_arn].logging is True

    # Test S3 Get Bucket Policy
    @mock_aws
    def test_get_bucket_policy(self):
        s3_client = client("s3")
        bucket_name = "test-bucket"
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
        s3_client.create_bucket(Bucket=bucket_name)
        ssl_policy = '{"Version": "2012-10-17","Id": "PutObjPolicy","Statement": [{"Sid": "s3-bucket-ssl-requests-only","Effect": "Deny","Principal": "*","Action": "s3:GetObject","Resource": "arn:aws:s3:::bucket_test_us/*","Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}'
        s3_client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=ssl_policy,
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        s3 = S3(aws_provider)
        assert len(s3.buckets) == 1
        assert s3.buckets[bucket_arn].name == bucket_name
        assert s3.buckets[bucket_arn].region == AWS_REGION_US_EAST_1
        assert s3.buckets[bucket_arn].policy == json.loads(ssl_policy)

    # Test S3 Get Bucket Encryption
    @mock_aws
    def test_get_bucket_encryption(self):
        # Generate S3 Client
        s3_client = client("s3")
        # Create S3 Bucket
        bucket_name = "test-bucket"
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
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
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        s3 = S3(aws_provider)
        assert len(s3.buckets) == 1
        assert s3.buckets[bucket_arn].name == bucket_name
        assert s3.buckets[bucket_arn].region == AWS_REGION_US_EAST_1
        assert s3.buckets[bucket_arn].encryption == "aws:kms"

    # Test S3 Get Bucket Ownership Controls
    @mock_aws
    def test_get_bucket_ownership_controls(self):
        # Generate S3 Client
        s3_client = client("s3")
        # Create S3 Bucket
        bucket_name = "test-bucket"
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
        s3_client.create_bucket(
            Bucket=bucket_name, ObjectOwnership="BucketOwnerEnforced"
        )

        # S3 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        s3 = S3(aws_provider)
        assert len(s3.buckets) == 1
        assert s3.buckets[bucket_arn].name == bucket_name
        assert s3.buckets[bucket_arn].region == AWS_REGION_US_EAST_1
        assert s3.buckets[bucket_arn].ownership == "BucketOwnerEnforced"

    # Test S3 Get Public Access Block
    @mock_aws
    def test_get_public_access_block(self):
        # Generate S3 Client
        s3_client = client("s3")
        # Create S3 Bucket
        bucket_name = "test-bucket"
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
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
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        s3 = S3(aws_provider)
        assert len(s3.buckets) == 1
        assert s3.buckets[bucket_arn].name == bucket_name
        assert s3.buckets[bucket_arn].region == AWS_REGION_US_EAST_1
        assert s3.buckets[bucket_arn].public_access_block.block_public_acls
        assert s3.buckets[bucket_arn].public_access_block.ignore_public_acls
        assert s3.buckets[bucket_arn].public_access_block.block_public_policy
        assert s3.buckets[bucket_arn].public_access_block.restrict_public_buckets

    # Test S3 Get Bucket Tagging
    @mock_aws
    def test_get_bucket_tagging(self):
        # Generate S3 Client
        s3_client = client("s3")
        # Create S3 Bucket
        bucket_name = "test-bucket"
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
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
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        s3 = S3(aws_provider)

        assert len(s3.buckets) == 1
        assert s3.buckets[bucket_arn].tags == [
            {"Key": "test", "Value": "test"},
        ]

    # Test S3 Control Account Get Public Access Block
    @mock_aws
    def test_get_public_access_blocks3_control(self):
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
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        s3control = S3Control(aws_provider)
        assert s3control.account_public_access_block.block_public_acls
        assert s3control.account_public_access_block.ignore_public_acls
        assert s3control.account_public_access_block.block_public_policy
        assert s3control.account_public_access_block.restrict_public_buckets

    # Test S3 Get Bucket Object Lock
    @mock_aws
    def test_get_object_lock_configuration(self):
        # Generate S3 Client
        s3_client = client("s3")
        # Create S3 Bucket
        bucket_name = "test-bucket"
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
        s3_client.create_bucket(
            Bucket=bucket_name,
            ObjectOwnership="BucketOwnerEnforced",
            ObjectLockEnabledForBucket=True,
        )

        # S3 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        s3 = S3(aws_provider)
        assert len(s3.buckets) == 1
        assert s3.buckets[bucket_arn].name == bucket_name
        assert s3.buckets[bucket_arn].region == AWS_REGION_US_EAST_1
        assert s3.buckets[bucket_arn].object_lock

    # Test S3 Get Bucket Replication
    @mock_aws
    def test_get_bucket_replication(self):
        # Generate S3 Client
        s3_client = client("s3")
        # Create S3 Bucket
        bucket_name = "test-bucket"
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
        s3_client.create_bucket(
            Bucket=bucket_name,
            ObjectOwnership="BucketOwnerEnforced",
        )
        s3_client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={"Status": "Enabled"},
        )
        s3_client.put_bucket_replication(
            Bucket=bucket_name,
            ReplicationConfiguration={
                "Role": "arn:aws:iam::123456789012:role/replication-role",
                "Rules": [
                    {
                        "ID": "rule1",
                        "Status": "Enabled",
                        "Prefix": "",
                        "Destination": {
                            "Bucket": bucket_arn,
                            "StorageClass": "STANDARD",
                        },
                    }
                ],
            },
        )

        # S3 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        s3 = S3(aws_provider)
        assert len(s3.buckets) == 1
        assert s3.buckets[bucket_arn].name == bucket_name
        assert s3.buckets[bucket_arn].region == AWS_REGION_US_EAST_1
        assert s3.buckets[bucket_arn].replication_rules[0].status == "Enabled"
        assert s3.buckets[bucket_arn].replication_rules[0].destination == bucket_arn

    # Test S3 Get Bucket Lifecycle
    @mock_aws
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_get_bucket_lifecycle(self):
        # Generate S3 Client
        s3_client = client("s3")

        # Create S3 Bucket
        bucket_name = "test-bucket"
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
        s3_client.create_bucket(
            Bucket=bucket_name,
            ObjectOwnership="BucketOwnerEnforced",
            ObjectLockEnabledForBucket=True,
        )

        # DEPRECATED: Put Bucket LifeCycle
        s3_client.put_bucket_lifecycle(
            Bucket=bucket_name,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "test",
                        "Status": "Enabled",
                        "Prefix": "test",
                    }
                ]
            },
        )

        # S3 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        s3 = S3(aws_provider)
        assert len(s3.buckets) == 1
        assert s3.buckets[bucket_arn].name == bucket_name
        assert s3.buckets[bucket_arn].region == AWS_REGION_US_EAST_1
        assert len(s3.buckets[bucket_arn].lifecycle) == 1
        assert s3.buckets[bucket_arn].lifecycle[0].id == "test"
        assert s3.buckets[bucket_arn].lifecycle[0].status == "Enabled"

    # Test S3 Get Bucket Notification Configuration
    @mock_aws
    def test_get_bucket_notification_configuration(self):
        # Generate S3 Client
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)
        # Create S3 Bucket
        bucket_name = "test-bucket"
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
        s3_client.create_bucket(
            Bucket=bucket_name,
            ObjectOwnership="BucketOwnerEnforced",
            ObjectLockEnabledForBucket=True,
        )
        s3_client.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration={
                "LambdaFunctionConfigurations": [
                    {
                        "LambdaFunctionArn": f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:123456789012:function:Test",
                        "Events": ["s3:ObjectCreated:*"],
                    }
                ]
            },
        )
        # S3 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        s3 = S3(aws_provider)
        assert len(s3.buckets) == 1
        assert s3.buckets[bucket_arn].name == bucket_name
        assert s3.buckets[bucket_arn].region == AWS_REGION_US_EAST_1
        assert s3.buckets[bucket_arn].notification_config

    # Test S3 Head Bucket
    @mock_aws
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_head_bucket(self):
        # Generate S3 Client
        s3_client = client("s3")

        # Create S3 Bucket
        bucket_name = "test-bucket"
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
        s3_client.create_bucket(
            Bucket=bucket_name,
            ObjectOwnership="BucketOwnerEnforced",
            ObjectLockEnabledForBucket=True,
        )

        # S3 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        s3 = S3(aws_provider)
        assert len(s3.buckets) == 1
        assert s3.buckets[bucket_arn].name == bucket_name
        assert s3._head_bucket(
            bucket_name=bucket_name,
        )
        assert s3.buckets[bucket_arn].region == AWS_REGION_US_EAST_1

    # Test S3Control List Access Points
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_list_access_points(self):
        arn = f"arn:aws:s3:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:accesspoint/test-access-point"

        # Generate S3 Client
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)

        # Generate Bucket
        s3_client.create_bucket(
            Bucket="test-bucket", ObjectOwnership="BucketOwnerEnforced"
        )
        sse_config = {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256",
                    }
                }
            ]
        }
        s3_client.put_bucket_encryption(
            Bucket="test-bucket", ServerSideEncryptionConfiguration=sse_config
        )

        # Generate S3Control Client
        s3control_client = client("s3control", region_name=AWS_REGION_US_EAST_1)

        s3control_client.create_access_point(
            AccountId=AWS_ACCOUNT_NUMBER,
            Name="test-access-point",
            Bucket="test-bucket",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        s3control = S3Control(aws_provider)

        assert len(s3control.access_points) == 1
        assert s3control.access_points[arn].account_id == AWS_ACCOUNT_NUMBER
        assert s3control.access_points[arn].name == "test-access-point"
        assert s3control.access_points[arn].bucket == "test-bucket"
        assert s3control.access_points[arn].region == AWS_REGION_US_EAST_1

    # Test S3Control Get Access Point
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_get_access_point(self):
        arn = f"arn:aws:s3:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:accesspoint/test-access-point"

        # Generate S3 Client
        s3_client = client("s3", region_name=AWS_REGION_US_EAST_1)

        # Generate Bucket
        s3_client.create_bucket(
            Bucket="test-bucket", ObjectOwnership="BucketOwnerEnforced"
        )
        sse_config = {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256",
                    }
                }
            ]
        }
        s3_client.put_bucket_encryption(
            Bucket="test-bucket", ServerSideEncryptionConfiguration=sse_config
        )

        # Generate S3Control Client
        s3control_client = client("s3control", region_name=AWS_REGION_US_EAST_1)

        s3control_client.create_access_point(
            AccountId=AWS_ACCOUNT_NUMBER,
            Name="test-access-point",
            Bucket="test-bucket",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        s3control = S3Control(aws_provider)

        assert len(s3control.access_points) == 1
        assert s3control.access_points[arn].account_id == AWS_ACCOUNT_NUMBER
        assert s3control.access_points[arn].name == "test-access-point"
        assert s3control.access_points[arn].bucket == "test-bucket"
        assert s3control.access_points[arn].region == AWS_REGION_US_EAST_1
        assert s3control.access_points[arn].public_access_block
        assert s3control.access_points[arn].public_access_block.block_public_acls
        assert s3control.access_points[arn].public_access_block.ignore_public_acls
        assert s3control.access_points[arn].public_access_block.block_public_policy
        assert s3control.access_points[arn].public_access_block.restrict_public_buckets
