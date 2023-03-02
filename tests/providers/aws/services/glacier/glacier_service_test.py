import json
from unittest.mock import patch

import botocore
from moto.core import DEFAULT_ACCOUNT_ID

from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.services.glacier.glacier_service import Glacier

# Mock Test Region
AWS_REGION = "eu-west-1"


# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call

vault_json_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "cross-account-upload",
            "Principal": {"AWS": [f"arn:aws:iam::{DEFAULT_ACCOUNT_ID}:root"]},
            "Effect": "Allow",
            "Action": [
                "glacier:UploadArchive",
                "glacier:InitiateMultipartUpload",
                "glacier:AbortMultipartUpload",
                "glacier:CompleteMultipartUpload",
            ],
            "Resource": [
                f"arn:aws:glacier:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:vaults/examplevault"
            ],
        }
    ],
}


def mock_make_api_call(self, operation_name, kwarg):
    """We have to mock every AWS API call using Boto3"""
    if operation_name == "ListVaults":
        return {
            "VaultList": [
                {
                    "VaultARN": f"arn:aws:glacier:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:vaults/examplevault",
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
def mock_generate_regional_clients(service, audit_info):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.services.glacier.glacier_service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_Glacier_Service:
    # Test Glacier Client
    def test__get_client__(self):
        glacier = Glacier(current_audit_info)
        assert glacier.regional_clients[AWS_REGION].__class__.__name__ == "Glacier"

    # Test Glacier Session
    def test__get_session__(self):
        glacier = Glacier(current_audit_info)
        assert glacier.session.__class__.__name__ == "Session"

    # Test Glacier Service
    def test__get_service__(self):
        glacier = Glacier(current_audit_info)
        assert glacier.service == "glacier"

    def test__list_vaults__(self):
        # Set partition for the service
        current_audit_info.audited_partition = "aws"
        glacier = Glacier(current_audit_info)
        vault_name = "examplevault"
        assert len(glacier.vaults) == 1
        assert glacier.vaults[vault_name]
        assert glacier.vaults[vault_name].name == vault_name
        assert (
            glacier.vaults[vault_name].arn
            == f"arn:aws:glacier:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:vaults/examplevault"
        )
        assert glacier.vaults[vault_name].region == AWS_REGION
        assert glacier.vaults[vault_name].tags == [{"test": "test"}]

    def test__get_vault_access_policy__(self):
        # Set partition for the service
        current_audit_info.audited_partition = "aws"
        glacier = Glacier(current_audit_info)
        vault_name = "examplevault"
        assert len(glacier.vaults) == 1
        assert glacier.vaults[vault_name]
        assert glacier.vaults[vault_name].name == vault_name
        assert (
            glacier.vaults[vault_name].arn
            == f"arn:aws:glacier:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:vaults/examplevault"
        )
        assert glacier.vaults[vault_name].region == AWS_REGION
        assert glacier.vaults[vault_name].access_policy == vault_json_policy
