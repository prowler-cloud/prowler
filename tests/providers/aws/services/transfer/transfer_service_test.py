from unittest.mock import patch

import botocore
from moto import mock_aws

from prowler.providers.aws.services.transfer.transfer_service import Protocol, Transfer
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call

SERVER_ID = "SERVICE_MANAGED::s-01234567890abcdef"
SERVER_ARN = f"arn:aws:transfer:us-east-1:{AWS_ACCOUNT_NUMBER}:server/{SERVER_ID}"


make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListServers":
        return {
            "Servers": [
                {
                    "Arn": f"arn:aws:transfer:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:server/{SERVER_ID}",
                    "ServerId": SERVER_ID,
                }
            ]
        }
    if operation_name == "DescribeServer":
        return {
            "Server": {
                "Arn": SERVER_ARN,
                "ServerId": SERVER_ID,
                "Protocols": ["SFTP"],
                "Tags": [{"Key": "key", "Value": "value"}],
            }
        }
    return make_api_call(self, operation_name, kwarg)


class Test_transfer_service:
    @mock_aws
    def test_get_client(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        transfer = Transfer(aws_provider)
        assert (
            transfer.regional_clients[AWS_REGION_US_EAST_1].__class__.__name__
            == "Transfer"
        )

    @mock_aws
    def test_get_session(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        transfer = Transfer(aws_provider)
        assert transfer.session.__class__.__name__ == "Session"

    @mock_aws
    def test_get_service(self):
        transfer = Transfer(set_mocked_aws_provider())
        assert transfer.service == "transfer"

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_list_servers(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        transfer = Transfer(aws_provider)
        assert len(transfer.servers) == 1
        assert transfer.servers[SERVER_ARN].arn == SERVER_ARN
        assert transfer.servers[SERVER_ARN].id == SERVER_ID
        assert transfer.servers[SERVER_ARN].region == "us-east-1"

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_describe_server(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        transfer = Transfer(aws_provider)
        assert transfer.servers[SERVER_ARN].arn == SERVER_ARN
        assert transfer.servers[SERVER_ARN].id == SERVER_ID
        assert len(transfer.servers[SERVER_ARN].protocols) == 1
        assert transfer.servers[SERVER_ARN].region == "us-east-1"
        assert transfer.servers[SERVER_ARN].tags == [{"Key": "key", "Value": "value"}]
        assert transfer.servers[SERVER_ARN].protocols[0] == Protocol.SFTP
