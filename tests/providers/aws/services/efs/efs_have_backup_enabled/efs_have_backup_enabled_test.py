from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CREATION_TOKEN = "fs-123"


class Test_efs_have_backup_enabled:
    @mock_aws
    def test_efs_valid_backup_policy(self):
        efs_client = client("efs", region_name=AWS_REGION_US_EAST_1)
        file_system = efs_client.create_file_system(
            CreationToken=CREATION_TOKEN, Backup=True
        )

        from prowler.providers.aws.services.efs.efs_service import EFS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.efs.efs_have_backup_enabled.efs_have_backup_enabled.efs_client",
            new=EFS(aws_provider),
        ):
            from prowler.providers.aws.services.efs.efs_have_backup_enabled.efs_have_backup_enabled import (
                efs_have_backup_enabled,
            )

            check = efs_have_backup_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"EFS {file_system['FileSystemId']} has backup enabled."
            )
            assert result[0].resource_id == file_system["FileSystemId"]
            assert (
                result[0].resource_arn
                == f"arn:aws:elasticfilesystem:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system['FileSystemId']}"
            )

    @mock_aws
    def test_efs_invalid_policy_backup_1(self):
        efs_client = client("efs", region_name=AWS_REGION_US_EAST_1)
        file_system = efs_client.create_file_system(
            CreationToken=CREATION_TOKEN, Backup=False
        )

        from prowler.providers.aws.services.efs.efs_service import EFS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.efs.efs_have_backup_enabled.efs_have_backup_enabled.efs_client",
            new=EFS(aws_provider),
        ):
            from prowler.providers.aws.services.efs.efs_have_backup_enabled.efs_have_backup_enabled import (
                efs_have_backup_enabled,
            )

            check = efs_have_backup_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"EFS {file_system['FileSystemId']} does not have backup enabled."
            )
            assert result[0].resource_id == file_system["FileSystemId"]
            assert (
                result[0].resource_arn
                == f"arn:aws:elasticfilesystem:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system['FileSystemId']}"
            )

    @mock_aws
    def test_efs_invalid_policy_backup_2(self):
        efs_client = client("efs", region_name=AWS_REGION_US_EAST_1)
        file_system = efs_client.create_file_system(
            CreationToken=CREATION_TOKEN, Backup=False
        )

        from prowler.providers.aws.services.efs.efs_service import EFS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.efs.efs_have_backup_enabled.efs_have_backup_enabled.efs_client",
            new=EFS(aws_provider),
        ):
            from prowler.providers.aws.services.efs.efs_have_backup_enabled.efs_have_backup_enabled import (
                efs_have_backup_enabled,
            )

            check = efs_have_backup_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"EFS {file_system['FileSystemId']} does not have backup enabled."
            )
            assert result[0].resource_id == file_system["FileSystemId"]
            assert (
                result[0].resource_arn
                == f"arn:aws:elasticfilesystem:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system['FileSystemId']}"
            )
