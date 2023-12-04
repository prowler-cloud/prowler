import json

from boto3 import client
from moto import mock_kms

from prowler.providers.aws.services.kms.kms_service import KMS
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)


class Test_ACM_Service:
    # Test KMS Service
    @mock_kms
    def test_service(self):
        # KMS client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        kms = KMS(audit_info)
        assert kms.service == "kms"

    # Test KMS Client
    @mock_kms
    def test_client(self):
        # KMS client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        kms = KMS(audit_info)
        for regional_client in kms.regional_clients.values():
            assert regional_client.__class__.__name__ == "KMS"

    # Test KMS Session
    @mock_kms
    def test__get_session__(self):
        # KMS client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        kms = KMS(audit_info)
        assert kms.session.__class__.__name__ == "Session"

    # Test KMS Session
    @mock_kms
    def test_audited_account(self):
        # KMS client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        kms = KMS(audit_info)
        assert kms.audited_account == AWS_ACCOUNT_NUMBER

    # Test KMS List Keys
    @mock_kms
    def test__list_keys__(self):
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_EU_WEST_1)
        # Create KMS keys
        key1 = kms_client.create_key()["KeyMetadata"]
        key2 = kms_client.create_key()["KeyMetadata"]
        # KMS client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        kms = KMS(audit_info)
        assert len(kms.keys) == 2
        assert kms.keys[0].arn == key1["Arn"]
        assert kms.keys[1].arn == key2["Arn"]

    # Test KMS Describe Keys
    @mock_kms
    def test__describe_key__(self):
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_EU_WEST_1)
        # Create KMS keys
        key1 = kms_client.create_key(
            Tags=[
                {"TagKey": "test", "TagValue": "test"},
            ],
        )["KeyMetadata"]
        # KMS client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        kms = KMS(audit_info)
        assert len(kms.keys) == 1
        assert kms.keys[0].arn == key1["Arn"]
        assert kms.keys[0].state == key1["KeyState"]
        assert kms.keys[0].origin == key1["Origin"]
        assert kms.keys[0].manager == key1["KeyManager"]
        assert kms.keys[0].tags == [
            {"TagKey": "test", "TagValue": "test"},
        ]

    # Test KMS Get rotation status
    @mock_kms
    def test__get_key_rotation_status__(self):
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_EU_WEST_1)
        # Create KMS keys
        key1 = kms_client.create_key()["KeyMetadata"]
        key2 = kms_client.create_key()["KeyMetadata"]
        kms_client.enable_key_rotation(KeyId=key2["KeyId"])
        # KMS client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        kms = KMS(audit_info)
        assert len(kms.keys) == 2
        assert kms.keys[0].arn == key1["Arn"]
        assert kms.keys[0].rotation_enabled is False
        assert kms.keys[1].arn == key2["Arn"]
        assert kms.keys[1].rotation_enabled is True

    # Test KMS Key policy
    @mock_kms
    def test__get_key_policy__(self):
        public_policy = json.dumps(
            {
                "Version": "2012-10-17",
                "Id": "key-default-1",
                "Statement": [
                    {
                        "Sid": "Enable IAM User Permissions",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "kms:*",
                        "Resource": "*",
                    }
                ],
            }
        )
        default_policy = json.dumps(
            {
                "Version": "2012-10-17",
                "Id": "key-default-1",
                "Statement": [
                    {
                        "Sid": "Enable IAM User Permissions",
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                        "Action": "kms:*",
                        "Resource": "*",
                    }
                ],
            }
        )
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_EU_WEST_1)
        # Create KMS keys
        key1 = kms_client.create_key(Policy=default_policy)["KeyMetadata"]
        key2 = kms_client.create_key(Policy=public_policy)["KeyMetadata"]
        # KMS client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        kms = KMS(audit_info)
        assert len(kms.keys) == 2
        assert kms.keys[0].arn == key1["Arn"]
        assert kms.keys[0].policy == json.loads(default_policy)
        assert kms.keys[1].arn == key2["Arn"]
        assert kms.keys[1].policy == json.loads(public_policy)
