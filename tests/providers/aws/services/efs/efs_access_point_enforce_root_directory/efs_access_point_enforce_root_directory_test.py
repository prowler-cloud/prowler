from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CREATION_TOKEN = "fs-123"


class Test_efs_access_point_enforce_root_directory:
    @mock_aws
    def test_efs_no_file_system(self):
        from prowler.providers.aws.services.efs.efs_service import EFS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.efs.efs_access_point_enforce_root_directory.efs_access_point_enforce_root_directory.efs_client",
            new=EFS(aws_provider),
        ):
            from prowler.providers.aws.services.efs.efs_access_point_enforce_root_directory.efs_access_point_enforce_root_directory import (
                efs_access_point_enforce_root_directory,
            )

            check = efs_access_point_enforce_root_directory()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_efs_no_access_point(self):
        efs_client = client("efs", region_name=AWS_REGION_US_EAST_1)
        efs_client.create_file_system(CreationToken=CREATION_TOKEN)
        from prowler.providers.aws.services.efs.efs_service import EFS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.efs.efs_access_point_enforce_root_directory.efs_access_point_enforce_root_directory.efs_client",
            new=EFS(aws_provider),
        ):
            from prowler.providers.aws.services.efs.efs_access_point_enforce_root_directory.efs_access_point_enforce_root_directory import (
                efs_access_point_enforce_root_directory,
            )

            check = efs_access_point_enforce_root_directory()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_efs_access_point_default_root_directory(self):
        efs_client = client("efs", region_name=AWS_REGION_US_EAST_1)
        file_system = efs_client.create_file_system(CreationToken=CREATION_TOKEN)

        access_point = efs_client.create_access_point(
            FileSystemId=file_system["FileSystemId"],
            PosixUser={"Uid": 1000, "Gid": 1000},
            RootDirectory={"Path": "/"},
        )

        from prowler.providers.aws.services.efs.efs_service import EFS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.efs.efs_access_point_enforce_root_directory.efs_access_point_enforce_root_directory.efs_client",
            new=EFS(aws_provider),
        ):
            from prowler.providers.aws.services.efs.efs_access_point_enforce_root_directory.efs_access_point_enforce_root_directory import (
                efs_access_point_enforce_root_directory,
            )

            check = efs_access_point_enforce_root_directory()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"EFS {file_system['FileSystemId']} has access points which allow access to the root directory: {access_point['AccessPointId']}."
            )
            assert result[0].resource_id == file_system["FileSystemId"]
            assert (
                result[0].resource_arn
                == f"arn:aws:elasticfilesystem:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system['FileSystemId']}"
            )

    @mock_aws
    def test_efs_access_point_enforced_root_directory(self):
        efs_client = client("efs", region_name=AWS_REGION_US_EAST_1)
        file_system = efs_client.create_file_system(CreationToken=CREATION_TOKEN)

        efs_client.create_access_point(
            FileSystemId=file_system["FileSystemId"],
            PosixUser={"Uid": 1000, "Gid": 1000},
            RootDirectory={"Path": "/notdefault"},
        )

        from prowler.providers.aws.services.efs.efs_service import EFS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.efs.efs_access_point_enforce_root_directory.efs_access_point_enforce_root_directory.efs_client",
            new=EFS(aws_provider),
        ):
            from prowler.providers.aws.services.efs.efs_access_point_enforce_root_directory.efs_access_point_enforce_root_directory import (
                efs_access_point_enforce_root_directory,
            )

            check = efs_access_point_enforce_root_directory()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"EFS {file_system['FileSystemId']} does not have any access point allowing access to the root directory."
            )
            assert result[0].resource_id == file_system["FileSystemId"]
            assert (
                result[0].resource_arn
                == f"arn:aws:elasticfilesystem:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system['FileSystemId']}"
            )
