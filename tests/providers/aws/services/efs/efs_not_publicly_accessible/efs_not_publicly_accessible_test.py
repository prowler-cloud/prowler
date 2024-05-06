from unittest import mock

from prowler.providers.aws.services.efs.efs_service import FileSystem

# Mock Test Region
AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"

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

# https://docs.aws.amazon.com/efs/latest/ug/access-control-block-public-access.html#what-is-a-public-policy
filesystem_policy_with_source_arn_condition = {
    "Version": "2012-10-17",
    "Id": "efs-policy-wizard-15ad9567-2546-4bbb-8168-5541b6fc0e55",
    "Statement": [
        {
            "Sid": "efs-statement-14a7191c-9401-40e7-a388-6af6cfb7dd9c",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": [
                "elasticfilesystem:ClientMount",
                "elasticfilesystem:ClientWrite",
                "elasticfilesystem:ClientRootAccess",
            ],
            "Condition": {
                "ArnEquals": {
                    "aws:SourceArn": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
                }
            },
        }
    ],
}

# https://docs.aws.amazon.com/efs/latest/ug/access-control-block-public-access.html#what-is-a-public-policy
filesystem_policy_with_mount_target_condition = {
    "Version": "2012-10-17",
    "Id": "efs-policy-wizard-15ad9567-2546-4bbb-8168-5541b6fc0e55",
    "Statement": [
        {
            "Sid": "efs-statement-14a7191c-9401-40e7-a388-6af6cfb7dd9c",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": [
                "elasticfilesystem:ClientMount",
                "elasticfilesystem:ClientWrite",
                "elasticfilesystem:ClientRootAccess",
            ],
            "Condition": {"Bool": {"elasticfilesystem:AccessedViaMountTarget": "true"}},
        }
    ],
}


class Test_efs_not_publicly_accessible:
    def test_efs_valid_policy(self):
        efs_client = mock.MagicMock
        efs_arn = f"arn:aws:elasticfilesystem:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system_id}"
        efs_client.filesystems = [
            FileSystem(
                id=file_system_id,
                arn=efs_arn,
                region=AWS_REGION,
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
            assert (
                result[0].status_extended
                == f"EFS {file_system_id} has a policy which does not allow access to any client within the VPC."
            )
            assert result[0].resource_id == file_system_id
            assert result[0].resource_arn == efs_arn
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags == []

    def test_efs_valid_policy_with_mount_target_condition(self):
        efs_client = mock.MagicMock
        efs_arn = f"arn:aws:elasticfilesystem:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system_id}"
        efs_client.filesystems = [
            FileSystem(
                id=file_system_id,
                arn=efs_arn,
                region=AWS_REGION,
                policy=filesystem_policy_with_mount_target_condition,
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
            assert (
                result[0].status_extended
                == f"EFS {file_system_id} has a policy which does not allow access to any client within the VPC."
            )
            assert result[0].resource_id == file_system_id
            assert result[0].resource_arn == efs_arn
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags == []

    def test_efs_valid_policy_with_source_arn_condition(self):
        efs_client = mock.MagicMock
        efs_arn = f"arn:aws:elasticfilesystem:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system_id}"
        efs_client.filesystems = [
            FileSystem(
                id=file_system_id,
                arn=efs_arn,
                region=AWS_REGION,
                policy=filesystem_policy_with_source_arn_condition,
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
            assert (
                result[0].status_extended
                == f"EFS {file_system_id} has a policy which does not allow access to any client within the VPC."
            )
            assert result[0].resource_id == file_system_id
            assert result[0].resource_arn == efs_arn
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags == []

    def test_efs_invalid_policy(self):
        efs_client = mock.MagicMock
        efs_arn = f"arn:aws:elasticfilesystem:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system_id}"

        efs_client.filesystems = [
            FileSystem(
                id=file_system_id,
                arn=efs_arn,
                region=AWS_REGION,
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
            assert (
                result[0].status_extended
                == f"EFS {file_system_id} has a policy which allows access to any client within the VPC."
            )
            assert result[0].resource_id == file_system_id
            assert result[0].resource_arn == efs_arn
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags == []

    def test_efs_no_policy(self):
        efs_client = mock.MagicMock
        efs_arn = f"arn:aws:elasticfilesystem:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system_id}"
        efs_client.filesystems = [
            FileSystem(
                id=file_system_id,
                arn=efs_arn,
                region=AWS_REGION,
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
            assert (
                result[0].status_extended
                == f"EFS {file_system_id} doesn't have any policy which means it grants full access to any client within the VPC."
            )
            assert result[0].resource_id == file_system_id
            assert result[0].resource_arn == efs_arn
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags == []
