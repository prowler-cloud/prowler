import json
from unittest.mock import patch

import botocore
from boto3 import client
from moto import mock_efs

from prowler.providers.aws.services.efs.efs_service import EFS
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

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


def mock_generate_regional_clients(service, audit_info, _):
    regional_client = audit_info.audit_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.lib.service.service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_EFS:
    # Test EFS Session
    def test__get_session__(self):
        access_analyzer = EFS(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]))
        assert access_analyzer.session.__class__.__name__ == "Session"

    # Test EFS Service
    def test__get_service__(self):
        access_analyzer = EFS(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]))
        assert access_analyzer.service == "efs"

    @mock_efs
    # Test EFS describe file systems
    def test__describe_file_systems__(self):
        efs_client = client("efs", AWS_REGION_EU_WEST_1)
        efs = efs_client.create_file_system(
            CreationToken=creation_token,
            Encrypted=True,
            Tags=[
                {"Key": "test", "Value": "test"},
            ],
        )
        filesystem = EFS(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]))
        assert len(filesystem.filesystems) == 1
        assert filesystem.filesystems[0].id == efs["FileSystemId"]
        assert filesystem.filesystems[0].encrypted == efs["Encrypted"]
        assert filesystem.filesystems[0].tags == [
            {"Key": "test", "Value": "test"},
        ]

    @mock_efs
    # Test EFS describe file systems
    def test__describe_file_system_policies__(self):
        efs_client = client("efs", AWS_REGION_EU_WEST_1)
        efs = efs_client.create_file_system(
            CreationToken=creation_token, Encrypted=True
        )
        filesystem = EFS(set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]))
        assert len(filesystem.filesystems) == 1
        assert filesystem.filesystems[0].id == efs["FileSystemId"]
        assert filesystem.filesystems[0].encrypted == efs["Encrypted"]
        assert filesystem.filesystems[0].backup_policy == backup_policy_status
        assert filesystem.filesystems[0].policy == filesystem_policy
