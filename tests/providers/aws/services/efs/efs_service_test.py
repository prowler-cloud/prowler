import json
from unittest.mock import patch

import botocore

from prowler.providers.aws.services.efs.efs_service import EFS
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call

FILE_SYSTEM_ID = "fs-c7a0456e"

CREATION_TOKEN = "console-d215fa78-1f83-4651-b026-facafd8a7da7"

FILESYSTEM_POLICY = {
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
    if operation_name == "DescribeFileSystems":
        return {
            "FileSystems": [
                {
                    "FileSystemId": FILE_SYSTEM_ID,
                    "Encrypted": True,
                    "Tags": [{"Key": "test", "Value": "test"}],
                    "AvailabilityZoneId": "az-12345",
                    "NumberOfMountTargets": 123,
                    "BackupPolicy": {"Status": "ENABLED"},
                    "Policy": json.dumps(FILESYSTEM_POLICY),
                }
            ]
        }
    if operation_name == "DescribeMountTargets":
        return {
            "MountTargets": [
                {
                    "MountTargetId": "fsmt-123",
                    "FileSystemId": FILE_SYSTEM_ID,
                    "SubnetId": "subnet-123",
                    "LifeCycleState": "available",
                    "OwnerId": AWS_ACCOUNT_NUMBER,
                    "VpcId": "vpc-123",
                }
            ]
        }
    if operation_name == "DescribeAccessPoints":
        return {
            "AccessPoints": [
                {
                    "AccessPointId": "fsap-123",
                    "AccessPointArn": f"arn:aws:elasticfilesystem:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:access-point/{FILE_SYSTEM_ID}/fsap-123",
                    "FileSystemId": FILE_SYSTEM_ID,
                    "RootDirectory": {"Path": "/"},
                    "PosixUser": {"Uid": 1000, "Gid": 1000},
                }
            ]
        }
    if operation_name == "DescribeFileSystemPolicy":
        return {"FileSystemId": FILE_SYSTEM_ID, "Policy": json.dumps(FILESYSTEM_POLICY)}
    if operation_name == "DescribeBackupPolicy":
        return {"BackupPolicy": {"Status": "ENABLED"}}
    return make_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_EFS:
    # Test EFS Session
    def test__get_session__(self):
        access_analyzer = EFS(set_mocked_aws_provider())
        assert access_analyzer.session.__class__.__name__ == "Session"

    # Test EFS Service
    def test__get_service__(self):
        access_analyzer = EFS(set_mocked_aws_provider())
        assert access_analyzer.service == "efs"

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    # Test EFS describe file systems
    def test_describe_file_systems(self):
        aws_provider = set_mocked_aws_provider()
        efs = EFS(aws_provider)
        efs_arn = f"arn:aws:elasticfilesystem:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{FILE_SYSTEM_ID}"
        assert len(efs.filesystems) == 1
        assert efs.filesystems[efs_arn].id == FILE_SYSTEM_ID
        assert efs.filesystems[efs_arn].encrypted
        assert efs.filesystems[efs_arn].availability_zone_id == "az-12345"
        assert efs.filesystems[efs_arn].number_of_mount_targets == 123
        assert efs.filesystems[efs_arn].tags == [
            {"Key": "test", "Value": "test"},
        ]

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    # Test EFS describe file systems policies
    def test_describe_file_system_policies(self):
        aws_provider = set_mocked_aws_provider()
        efs = EFS(aws_provider)
        efs_arn = f"arn:aws:elasticfilesystem:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{FILE_SYSTEM_ID}"
        assert len(efs.filesystems) == 1
        assert efs.filesystems[efs_arn].id == FILE_SYSTEM_ID
        assert efs.filesystems[efs_arn].encrypted
        assert efs.filesystems[efs_arn].backup_policy == "ENABLED"
        assert efs.filesystems[efs_arn].policy == FILESYSTEM_POLICY

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    # Test EFS describe mount targets
    def test_describe_mount_targets(self):
        aws_provider = set_mocked_aws_provider()
        efs = EFS(aws_provider)
        assert len(efs.filesystems) == 1
        efs_arn = f"arn:aws:elasticfilesystem:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{FILE_SYSTEM_ID}"
        assert (
            efs.filesystems[efs_arn].mount_targets[0].file_system_id == FILE_SYSTEM_ID
        )
        assert efs.filesystems[efs_arn].mount_targets[0].id == "fsmt-123"
        assert efs.filesystems[efs_arn].mount_targets[0].subnet_id == "subnet-123"

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    # Test EFS describe access points
    def test_describe_access_points(self):
        aws_provider = set_mocked_aws_provider()
        efs = EFS(aws_provider)
        assert len(efs.filesystems) == 1
        efs_arn = f"arn:aws:elasticfilesystem:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{FILE_SYSTEM_ID}"
        assert (
            efs.filesystems[efs_arn].access_points[0].file_system_id == FILE_SYSTEM_ID
        )
        assert efs.filesystems[efs_arn].access_points[0].id == "fsap-123"
        assert efs.filesystems[efs_arn].access_points[0].root_directory_path == "/"
        assert efs.filesystems[efs_arn].access_points[0].posix_user == {
            "Uid": 1000,
            "Gid": 1000,
        }
