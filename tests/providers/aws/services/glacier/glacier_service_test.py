import json
from unittest.mock import patch

import botocore

from prowler.providers.aws.services.glacier.glacier_service import Glacier
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)

# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call

TEST_VAULT_ARN = (
    f"arn:aws:glacier:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:vaults/examplevault"
)
vault_json_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "cross-account-upload",
            "Principal": {"AWS": [f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"]},
            "Effect": "Allow",
            "Action": [
                "glacier:UploadArchive",
                "glacier:InitiateMultipartUpload",
                "glacier:AbortMultipartUpload",
                "glacier:CompleteMultipartUpload",
            ],
            "Resource": [TEST_VAULT_ARN],
        }
    ],
}


def mock_make_api_call(self, operation_name, kwarg):
    """We have to mock every AWS API call using Boto3"""
    if operation_name == "ListVaults":
        return {
            "VaultList": [
                {
                    "VaultARN": TEST_VAULT_ARN,
                    "VaultName": "examplevault",
                    "CreationDate": "2012-03-16T22:22:47.214Z",
                    "LastInventoryDate": "2012-03-21T22:06:51.218Z",
                    "NumberOfArchives": 2,
                    "SizeInBytes": 12334,
                },
            ],
        }

    if operation_name == "GetVaultAccessPolicy":
        return {"policy": {"Policy": json.dumps(vault_json_policy)}}

    if operation_name == "ListTagsForVault":
        return {"Tags": {"test": "test"}}

    return make_api_call(self, operation_name, kwarg)


# Mock generate_regional_clients()
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
class Test_Glacier_Service:
    # Test Glacier Client
    def test__get_client__(self):
        glacier = Glacier(
            set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1])
        )
        assert (
            glacier.regional_clients[AWS_REGION_EU_WEST_1].__class__.__name__
            == "Glacier"
        )

    # Test Glacier Session
    def test__get_session__(self):
        glacier = Glacier(
            set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1])
        )
        assert glacier.session.__class__.__name__ == "Session"

    # Test Glacier Service
    def test__get_service__(self):
        glacier = Glacier(
            set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1])
        )
        assert glacier.service == "glacier"

    def test__list_vaults__(self):
        # Set partition for the service
        glacier = Glacier(
            set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1])
        )
        vault_name = "examplevault"
        assert len(glacier.vaults) == 1
        assert glacier.vaults[TEST_VAULT_ARN]
        assert glacier.vaults[TEST_VAULT_ARN].name == vault_name
        assert (
            glacier.vaults[TEST_VAULT_ARN].arn
            == f"arn:aws:glacier:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:vaults/examplevault"
        )
        assert glacier.vaults[TEST_VAULT_ARN].region == AWS_REGION_EU_WEST_1
        assert glacier.vaults[TEST_VAULT_ARN].tags == [{"test": "test"}]

    def test__get_vault_access_policy__(self):
        # Set partition for the service
        glacier = Glacier(
            set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1])
        )
        vault_name = "examplevault"
        assert len(glacier.vaults) == 1
        assert glacier.vaults[TEST_VAULT_ARN]
        assert glacier.vaults[TEST_VAULT_ARN].name == vault_name
        assert (
            glacier.vaults[TEST_VAULT_ARN].arn
            == f"arn:aws:glacier:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:vaults/examplevault"
        )
        assert glacier.vaults[TEST_VAULT_ARN].region == AWS_REGION_EU_WEST_1
        assert glacier.vaults[TEST_VAULT_ARN].access_policy == vault_json_policy
