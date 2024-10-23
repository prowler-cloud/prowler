from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

CREATION_TOKEN = "fs-123"


class Test_efs_multi_az_enabled:
    @mock_aws
    def test_no_efs_filesystems(self):
        from prowler.providers.aws.services.efs.efs_service import EFS

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.efs.efs_multi_az_enabled.efs_multi_az_enabled.efs_client",
                new=EFS(aws_provider),
            ):
                from prowler.providers.aws.services.efs.efs_multi_az_enabled.efs_multi_az_enabled import (
                    efs_multi_az_enabled,
                )

                check = efs_multi_az_enabled()
                result = check.execute()
                assert len(result) == 0

    @mock_aws
    def test_efs_multi_az_availability_zone_id_present(self):
        efs_client = client("efs", region_name=AWS_REGION_EU_WEST_1)
        file_system = efs_client.create_file_system(
            CreationToken=CREATION_TOKEN, Backup=False
        )
        efs_arn = f"arn:aws:elasticfilesystem:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system['FileSystemId']}"
        from prowler.providers.aws.services.efs.efs_service import EFS

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.efs.efs_multi_az_enabled.efs_multi_az_enabled.efs_client",
                new=EFS(aws_provider),
            ) as service_client:
                from prowler.providers.aws.services.efs.efs_multi_az_enabled.efs_multi_az_enabled import (
                    efs_multi_az_enabled,
                )

                service_client.filesystems[efs_arn].availability_zone_id = "az-123"
                check = efs_multi_az_enabled()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"EFS {file_system['FileSystemId']} is a Single-AZ file system."
                )
                assert result[0].resource_id == file_system["FileSystemId"]
                assert (
                    result[0].resource_arn
                    == f"arn:aws:elasticfilesystem:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system['FileSystemId']}"
                )

    @mock_aws
    def test_efs_multi_az_single_mount_target(self):
        efs_client = client("efs", region_name=AWS_REGION_EU_WEST_1)
        file_system = efs_client.create_file_system(
            CreationToken=CREATION_TOKEN, Backup=False
        )
        efs_arn = f"arn:aws:elasticfilesystem:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system['FileSystemId']}"
        from prowler.providers.aws.services.efs.efs_service import EFS

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.efs.efs_multi_az_enabled.efs_multi_az_enabled.efs_client",
                new=EFS(aws_provider),
            ) as service_client:
                from prowler.providers.aws.services.efs.efs_multi_az_enabled.efs_multi_az_enabled import (
                    efs_multi_az_enabled,
                )

                service_client.filesystems[efs_arn].number_of_mount_targets = 1
                check = efs_multi_az_enabled()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"EFS {file_system['FileSystemId']} is a Multi-AZ file system but with only one mount target."
                )
                assert result[0].resource_id == file_system["FileSystemId"]
                assert (
                    result[0].resource_arn
                    == f"arn:aws:elasticfilesystem:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system['FileSystemId']}"
                )

    @mock_aws
    def test_efs_multi_az_enabled(self):
        efs_client = client("efs", region_name=AWS_REGION_EU_WEST_1)
        file_system = efs_client.create_file_system(
            CreationToken=CREATION_TOKEN, Backup=False
        )
        efs_arn = f"arn:aws:elasticfilesystem:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system['FileSystemId']}"
        from prowler.providers.aws.services.efs.efs_service import EFS

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.efs.efs_multi_az_enabled.efs_multi_az_enabled.efs_client",
                new=EFS(aws_provider),
            ) as service_client:
                from prowler.providers.aws.services.efs.efs_multi_az_enabled.efs_multi_az_enabled import (
                    efs_multi_az_enabled,
                )

                service_client.filesystems[efs_arn].number_of_mount_targets = 12
                check = efs_multi_az_enabled()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"EFS {file_system['FileSystemId']} is a Multi-AZ file system with more than one mount target."
                )
                assert result[0].resource_id == file_system["FileSystemId"]
                assert (
                    result[0].resource_arn
                    == f"arn:aws:elasticfilesystem:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system['FileSystemId']}"
                )
