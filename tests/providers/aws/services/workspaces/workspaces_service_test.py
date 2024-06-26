from unittest.mock import patch
from uuid import uuid4

import botocore

from prowler.providers.aws.services.workspaces.workspaces_service import WorkSpaces
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider

workspace_id = str(uuid4())

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeWorkspaces":
        return {
            "Workspaces": [
                {
                    "WorkspaceId": workspace_id,
                    "UserVolumeEncryptionEnabled": True,
                    "RootVolumeEncryptionEnabled": True,
                    "SubnetId": "subnet-1234567890",
                },
            ],
        }
    if operation_name == "DescribeTags":
        return {
            "TagList": [
                {"Key": "test", "Value": "test"},
            ]
        }
    return make_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_WorkSpaces_Service:
    # Test WorkSpaces Service
    def test_service(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        workspaces = WorkSpaces(aws_provider)
        assert workspaces.service == "workspaces"

    # Test WorkSpaces client
    def test_client(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        workspaces = WorkSpaces(aws_provider)
        for reg_client in workspaces.regional_clients.values():
            assert reg_client.__class__.__name__ == "WorkSpaces"

    # Test WorkSpaces session
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        workspaces = WorkSpaces(aws_provider)
        assert workspaces.session.__class__.__name__ == "Session"

    # Test WorkSpaces describe workspaces
    def test__describe_workspaces__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        workspaces = WorkSpaces(aws_provider)
        assert len(workspaces.workspaces) == 1
        assert workspaces.workspaces[0].id == workspace_id
        assert workspaces.workspaces[0].region == AWS_REGION_EU_WEST_1
        assert workspaces.workspaces[0].tags == [
            {"Key": "test", "Value": "test"},
        ]
        assert workspaces.workspaces[0].user_volume_encryption_enabled
        assert workspaces.workspaces[0].root_volume_encryption_enabled
