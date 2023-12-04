from re import search
from unittest import mock

from prowler.providers.aws.services.efs.efs_service import FileSystem
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
)

file_system_id = "fs-c7a0456e"


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

filesystem_invalid_policy = {
    "Id": "1",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["elasticfilesystem:ClientMount"],
            "Principal": {"AWS": "*"},
        }
    ],
}


class Test_efs_not_publicly_accessible:
    def test_efs_valid_policy(self):
        efs_client = mock.MagicMock
        efs_arn = f"arn:aws:elasticfilesystem:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system_id}"
        efs_client.filesystems = [
            FileSystem(
                id=file_system_id,
                arn=efs_arn,
                region=AWS_REGION_EU_WEST_1,
                policy=filesystem_policy,
                backup_policy=None,
                encrypted=True,
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.efs.efs_service.EFS",
            efs_client,
        ):
            from prowler.providers.aws.services.efs.efs_not_publicly_accessible.efs_not_publicly_accessible import (
                efs_not_publicly_accessible,
            )

            check = efs_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "has a policy which does not allow access to everyone",
                result[0].status_extended,
            )
            assert result[0].resource_id == file_system_id
            assert result[0].resource_arn == efs_arn

    def test_efs_invalid_policy(self):
        efs_client = mock.MagicMock
        efs_arn = f"arn:aws:elasticfilesystem:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system_id}"

        efs_client.filesystems = [
            FileSystem(
                id=file_system_id,
                arn=efs_arn,
                region=AWS_REGION_EU_WEST_1,
                policy=filesystem_invalid_policy,
                backup_policy=None,
                encrypted=True,
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.efs.efs_service.EFS",
            efs_client,
        ):
            from prowler.providers.aws.services.efs.efs_not_publicly_accessible.efs_not_publicly_accessible import (
                efs_not_publicly_accessible,
            )

            check = efs_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "has a policy which allows access to everyone",
                result[0].status_extended,
            )
            assert result[0].resource_id == file_system_id
            assert result[0].resource_arn == efs_arn

    def test_efs_no_policy(self):
        efs_client = mock.MagicMock
        efs_arn = f"arn:aws:elasticfilesystem:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system_id}"
        efs_client.filesystems = [
            FileSystem(
                id=file_system_id,
                arn=efs_arn,
                region=AWS_REGION_EU_WEST_1,
                policy=None,
                backup_policy=None,
                encrypted=True,
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.efs.efs_service.EFS",
            efs_client,
        ):
            from prowler.providers.aws.services.efs.efs_not_publicly_accessible.efs_not_publicly_accessible import (
                efs_not_publicly_accessible,
            )

            check = efs_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "doesn't have any policy which means it grants full access to any client",
                result[0].status_extended,
            )
            assert result[0].resource_id == file_system_id
            assert result[0].resource_arn == efs_arn
