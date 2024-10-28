from boto3 import client
from mock import patch
from moto import mock_aws

from prowler.providers.aws.services.fsx.fsx_service import FSx
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_US_EAST_1
    )
    regional_client.region = AWS_REGION_US_EAST_1
    return {AWS_REGION_US_EAST_1: regional_client}


@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_FSx_Service:
    # Test FSx Service
    def test_service(self):
        aws_provider = set_mocked_aws_provider()
        fsx = FSx(aws_provider)
        assert fsx.service == "fsx"

    # Test FSx Client
    def test_client(self):
        aws_provider = set_mocked_aws_provider()
        fsx = FSx(aws_provider)
        assert fsx.client.__class__.__name__ == "FSx"

    # Test FSx Session
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider()
        fsx = FSx(aws_provider)
        assert fsx.session.__class__.__name__ == "Session"

    # Test FSx Session
    def test_audited_account(self):
        aws_provider = set_mocked_aws_provider()
        fsx = FSx(aws_provider)
        assert fsx.audited_account == AWS_ACCOUNT_NUMBER

    # Test FSx Describe File Systems
    @mock_aws
    def test_describe_file_systems(self):
        fsx_client = client("fsx", region_name=AWS_REGION_US_EAST_1)
        file_system = fsx_client.create_file_system(
            FileSystemType="LUSTRE",
            StorageCapacity=1200,
            LustreConfiguration={"CopyTagsToBackups": True},
            Tags=[{"Key": "Name", "Value": "Test"}],
            SubnetIds=["subnet-12345678", "subnet-12345670"],
        )
        arn = f"arn:aws:fsx:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system['FileSystem']['FileSystemId']}"
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        fsx = FSx(aws_provider)
        assert len(fsx.file_systems) == 1
        assert fsx.file_systems[arn].id == file_system["FileSystem"]["FileSystemId"]
        assert fsx.file_systems[arn].type == "LUSTRE"
        assert fsx.file_systems[arn].copy_tags_to_backups
        assert fsx.file_systems[arn].region == AWS_REGION_US_EAST_1
        assert fsx.file_systems[arn].tags == [{"Key": "Name", "Value": "Test"}]
        assert (
            fsx.file_systems[arn].subnet_ids == file_system["FileSystem"]["SubnetIds"]
        )
