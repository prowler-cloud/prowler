import json
from unittest.mock import patch

import botocore
from boto3 import client, session
from moto import mock_efs

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.efs.efs_service import EFS

# Mock Test Region
AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"

# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call

file_system_id = "fs-c7a0456e"

creation_token = "console-d215fa78-1f83-4651-b026-facafd8a7da7"

backup_policy_status = "ENABLED"

filesystem_policy = {
    "Id": "1",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["elasticfilesystem:ClientMount"],
            "Principal": {"AWS": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"},
        }
    ],
}


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeFileSystemPolicy":
        return {"FileSystemId": file_system_id, "Policy": json.dumps(filesystem_policy)}
    if operation_name == "DescribeBackupPolicy":
        return {"BackupPolicy": {"Status": backup_policy_status}}
    return make_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(service, audit_info):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.services.efs.efs_service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_EFS:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
        )
        return audit_info

    # Test EFS Session
    def test__get_session__(self):
        access_analyzer = EFS(self.set_mocked_audit_info())
        assert access_analyzer.session.__class__.__name__ == "Session"

    # Test EFS Service
    def test__get_service__(self):
        access_analyzer = EFS(self.set_mocked_audit_info())
        assert access_analyzer.service == "efs"

    @mock_efs
    # Test EFS describe file systems
    def test__describe_file_systems__(self):
        efs_client = client("efs", AWS_REGION)
        efs = efs_client.create_file_system(
            CreationToken=creation_token,
            Encrypted=True,
            Tags=[
                {"Key": "test", "Value": "test"},
            ],
        )
        filesystem = EFS(self.set_mocked_audit_info())
        assert len(filesystem.filesystems) == 1
        assert filesystem.filesystems[0].id == efs["FileSystemId"]
        assert filesystem.filesystems[0].encrypted == efs["Encrypted"]
        assert filesystem.filesystems[0].tags == [
            {"Key": "test", "Value": "test"},
        ]

    @mock_efs
    # Test EFS describe file systems
    def test__describe_file_system_policies__(self):
        efs_client = client("efs", AWS_REGION)
        efs = efs_client.create_file_system(
            CreationToken=creation_token, Encrypted=True
        )
        filesystem = EFS(self.set_mocked_audit_info())
        assert len(filesystem.filesystems) == 1
        assert filesystem.filesystems[0].id == efs["FileSystemId"]
        assert filesystem.filesystems[0].encrypted == efs["Encrypted"]
        assert filesystem.filesystems[0].backup_policy == backup_policy_status
        assert filesystem.filesystems[0].policy == filesystem_policy
