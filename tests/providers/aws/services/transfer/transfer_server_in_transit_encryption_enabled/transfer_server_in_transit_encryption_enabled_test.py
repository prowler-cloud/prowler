from unittest import mock
from unittest.mock import patch

import botocore
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

SERVER_ID = "s-01234567890abcdef"
SERVER_ARN = (
    f"arn:aws:transfer:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:server/{SERVER_ID}"
)

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call_encrypted(self, operation_name, kwarg):
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
            }
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_unencrypted(self, operation_name, kwarg):
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
                "Protocols": ["FTP", "FTPS", "SFTP", "AS2"],
            }
        }
    return make_api_call(self, operation_name, kwarg)


class Test_transfer_server_encryption_in_transit:
    @mock_aws
    def test_no_servers(self):
        from prowler.providers.aws.services.transfer.transfer_service import Transfer

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.transfer.transfer_server_in_transit_encryption_enabled.transfer_server_in_transit_encryption_enabled.transfer_client",
                new=Transfer(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.transfer.transfer_server_in_transit_encryption_enabled.transfer_server_in_transit_encryption_enabled import (
                    transfer_server_in_transit_encryption_enabled,
                )

                check = transfer_server_in_transit_encryption_enabled()
                result = check.execute()

                assert len(result) == 0

    @patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_encrypted
    )
    @mock_aws
    def test_transfer_server_encryption_enabled(self):
        from prowler.providers.aws.services.transfer.transfer_service import Transfer

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.transfer.transfer_server_in_transit_encryption_enabled.transfer_server_in_transit_encryption_enabled.transfer_client",
                new=Transfer(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.transfer.transfer_server_in_transit_encryption_enabled.transfer_server_in_transit_encryption_enabled import (
                    transfer_server_in_transit_encryption_enabled,
                )

                check = transfer_server_in_transit_encryption_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Transfer Server {SERVER_ID} does have encryption in transit enabled."
                )
                assert result[0].resource_id == SERVER_ID
                assert result[0].resource_arn == SERVER_ARN
                assert result[0].region == AWS_REGION_US_EAST_1

    @patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_unencrypted
    )
    @mock_aws
    def test_transfer_server_encryption_disabled(self):
        from prowler.providers.aws.services.transfer.transfer_service import Transfer

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.transfer.transfer_server_in_transit_encryption_enabled.transfer_server_in_transit_encryption_enabled.transfer_client",
                new=Transfer(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.transfer.transfer_server_in_transit_encryption_enabled.transfer_server_in_transit_encryption_enabled import (
                    transfer_server_in_transit_encryption_enabled,
                )

                check = transfer_server_in_transit_encryption_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"Transfer Server {SERVER_ID} does not have encryption in transit enabled."
                )
                assert result[0].resource_id == SERVER_ID
                assert result[0].resource_arn == SERVER_ARN
                assert result[0].region == AWS_REGION_US_EAST_1
