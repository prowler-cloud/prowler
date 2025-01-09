from unittest.mock import patch

import botocore
from moto import mock_aws

from prowler.providers.aws.services.storagegateway.storagegateway_service import (
    StorageGateway,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

test_gateway = "sgw-12A3456B"
test_gateway_arn = f"arn:aws:storagegateway:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:gateway/{test_gateway}"
test_iam_role = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/my-role"
test_kms_key = f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/b72aaa2a-2222-99tt-12345690qwe"
test_share_nfs = "share-nfs2wwe"
test_share_arn_nfs = f"arn:aws:storagegateway:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:share/{test_share_nfs}"
test_share_smb = "share-smb2wwe"
test_share_arn_smb = f"arn:aws:storagegateway:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:share/{test_share_smb}"

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "CreateNFSFileShare":
        return {"FileShareARN": f"{test_share_arn_nfs}"}
    if operation_name == "CreateSMBFileShare":
        return {"FileShareARN": f"{test_share_arn_smb}"}
    if operation_name == "ListFileShares":
        return {
            "FileShareInfoList": [
                {
                    "FileShareType": "NFS",
                    "FileShareARN": f"{test_share_arn_nfs}",
                    "FileShareId": f"{test_share_nfs}",
                    "FileShareStatus": "AVAILABLE",
                    "GatewayARN": f"{test_gateway_arn}",
                },
                {
                    "FileShareType": "SMB",
                    "FileShareARN": f"{test_share_arn_smb}",
                    "FileShareId": f"{test_share_smb}",
                    "FileShareStatus": "AVAILABLE",
                    "GatewayARN": f"{test_gateway_arn}",
                },
            ]
        }
    if operation_name == "DescribeNFSFileShares":
        return {
            "NFSFileShareInfoList": [
                {
                    "FileShareType": "NFS",
                    "FileShareARN": f"{test_share_arn_nfs}",
                    "FileShareId": f"{test_share_nfs}",
                    "FileShareStatus": "AVAILABLE",
                    "GatewayARN": f"{test_gateway_arn}",
                    "Tags": [
                        {"Key": "test", "Value": "test"},
                    ],
                    "KMSEncrypted": True,
                    "KMSKey": f"{test_kms_key}",
                },
            ]
        }
    if operation_name == "DescribeSMBFileShares":
        return {
            "SMBFileShareInfoList": [
                {
                    "FileShareType": "SMB",
                    "FileShareARN": f"{test_share_arn_smb}",
                    "FileShareId": f"{test_share_smb}",
                    "FileShareStatus": "AVAILABLE",
                    "GatewayARN": f"{test_gateway_arn}",
                    "KMSEncrypted": False,
                    "KMSKey": "",
                },
            ]
        }
    if operation_name == "ListGateways":
        return {
            "Gateways": [
                {
                    "GatewayId": f"{test_gateway}",
                    "GatewayARN": f"{test_gateway_arn}",
                    "GatewayType": "fsx",
                    "GatewayName": "test",
                    "HostEnvironment": "EC2",
                },
            ]
        }
    return make_api_call(self, operation_name, kwarg)


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_StorageGateway_Service:

    # Test SGW Service
    @mock_aws
    def test_service(self):
        # SGW client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        storagegateway = StorageGateway(aws_provider)
        assert storagegateway.service == "storagegateway"

    # Test SGW Describe FileShares
    @mock_aws
    def test__describe_file_shares__(self):
        # StorageGateway client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        sgw = StorageGateway(aws_provider)
        assert len(sgw.fileshares) == 2
        assert sgw.fileshares[0].id == "share-nfs2wwe"
        assert sgw.fileshares[0].fs_type == "NFS"
        assert sgw.fileshares[0].status == "AVAILABLE"
        assert (
            sgw.fileshares[0].gateway_arn
            == "arn:aws:storagegateway:us-east-1:123456789012:gateway/sgw-12A3456B"
        )
        assert sgw.fileshares[0].kms
        assert (
            sgw.fileshares[0].kms_key
            == "arn:aws:kms:us-east-1:123456789012:key/b72aaa2a-2222-99tt-12345690qwe"
        )
        assert sgw.fileshares[0].tags == [
            {"Key": "test", "Value": "test"},
        ]
        assert sgw.fileshares[1].id == "share-smb2wwe"
        assert sgw.fileshares[1].fs_type == "SMB"
        assert sgw.fileshares[1].status == "AVAILABLE"
        assert (
            sgw.fileshares[1].gateway_arn
            == "arn:aws:storagegateway:us-east-1:123456789012:gateway/sgw-12A3456B"
        )
        assert not sgw.fileshares[1].kms
        assert sgw.fileshares[1].kms_key == ""
        assert sgw.fileshares[1].tags == []

    @mock_aws
    def test__describe_gateways__(self):
        # StorageGateway client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        sgw = StorageGateway(aws_provider)
        assert len(sgw.gateways) == 1
        assert sgw.gateways[0].id == f"{test_gateway}"
        assert sgw.gateways[0].type == "fsx"
        assert sgw.gateways[0].name == "test"
        assert (
            sgw.gateways[0].arn
            == "arn:aws:storagegateway:us-east-1:123456789012:gateway/sgw-12A3456B"
        )
        assert sgw.gateways[0].environment == "EC2"
