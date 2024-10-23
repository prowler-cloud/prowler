from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.fsx.fsx_service import FSx
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider


class Test_fsx_windows_file_system_multi_az:
    @mock_aws
    def test_fsx_no_file_system(self):
        client("fsx", region_name=AWS_REGION_EU_WEST_1)

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.fsx.fsx_windows_file_system_multi_az_enabled.fsx_windows_file_system_multi_az_enabled.fsx_client",
            new=FSx(aws_provider),
        ):
            from prowler.providers.aws.services.fsx.fsx_windows_file_system_multi_az_enabled.fsx_windows_file_system_multi_az_enabled import (
                fsx_windows_file_system_multi_az_enabled,
            )

            check = fsx_windows_file_system_multi_az_enabled()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_fsx_file_system_not_windows(self):
        fsx_client = client("fsx", region_name=AWS_REGION_EU_WEST_1)
        fsx_client.create_file_system(
            FileSystemType="LUSTRE",
            StorageCapacity=1200,
            LustreConfiguration={"CopyTagsToBackups": True},
            Tags=[{"Key": "Name", "Value": "Test"}],
            SubnetIds=["subnet-12345678"],
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.fsx.fsx_windows_file_system_multi_az_enabled.fsx_windows_file_system_multi_az_enabled.fsx_client",
            new=FSx(aws_provider),
        ):
            from prowler.providers.aws.services.fsx.fsx_windows_file_system_multi_az_enabled.fsx_windows_file_system_multi_az_enabled import (
                fsx_windows_file_system_multi_az_enabled,
            )

            check = fsx_windows_file_system_multi_az_enabled()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_fsx_windows_not_multi_az(self):
        fsx_client = client("fsx", region_name=AWS_REGION_EU_WEST_1)
        file_system = fsx_client.create_file_system(
            FileSystemType="WINDOWS",
            StorageCapacity=1200,
            OpenZFSConfiguration={
                "CopyTagsToVolumes": False,
                "DeploymentType": "SINGLE_AZ_1",
                "ThroughputCapacity": 12,
            },
            Tags=[{"Key": "Name", "Value": "Test"}],
            SubnetIds=["subnet-12345678"],
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.fsx.fsx_windows_file_system_multi_az_enabled.fsx_windows_file_system_multi_az_enabled.fsx_client",
            new=FSx(aws_provider),
        ):
            from prowler.providers.aws.services.fsx.fsx_windows_file_system_multi_az_enabled.fsx_windows_file_system_multi_az_enabled import (
                fsx_windows_file_system_multi_az_enabled,
            )

            check = fsx_windows_file_system_multi_az_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"FSx Windows file system {file_system['FileSystem']['FileSystemId']} is not configured for Multi-AZ deployment."
            )
            assert result[0].resource_id == file_system["FileSystem"]["FileSystemId"]
            assert (
                result[0].resource_arn
                == f"arn:aws:fsx:{AWS_REGION_EU_WEST_1}:123456789012:file-system/{file_system['FileSystem']['FileSystemId']}"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_fsx_windows_multi_az(self):
        fsx_client = client("fsx", region_name=AWS_REGION_EU_WEST_1)
        file_system = fsx_client.create_file_system(
            FileSystemType="WINDOWS",
            StorageCapacity=1200,
            OpenZFSConfiguration={
                "CopyTagsToVolumes": True,
                "DeploymentType": "MULTI_AZ_1",
                "ThroughputCapacity": 12,
            },
            Tags=[{"Key": "Name", "Value": "Test"}],
            SubnetIds=["subnet-12345678", "subnet-12345670"],
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.fsx.fsx_windows_file_system_multi_az_enabled.fsx_windows_file_system_multi_az_enabled.fsx_client",
            new=FSx(aws_provider),
        ):
            from prowler.providers.aws.services.fsx.fsx_windows_file_system_multi_az_enabled.fsx_windows_file_system_multi_az_enabled import (
                fsx_windows_file_system_multi_az_enabled,
            )

            check = fsx_windows_file_system_multi_az_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"FSx Windows file system {file_system['FileSystem']['FileSystemId']} is configured for Multi-AZ deployment."
            )
            assert result[0].resource_id == file_system["FileSystem"]["FileSystemId"]
            assert (
                result[0].resource_arn
                == f"arn:aws:fsx:{AWS_REGION_EU_WEST_1}:123456789012:file-system/{file_system['FileSystem']['FileSystemId']}"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
