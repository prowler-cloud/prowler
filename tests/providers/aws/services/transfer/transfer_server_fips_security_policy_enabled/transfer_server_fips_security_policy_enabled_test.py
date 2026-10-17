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
CHECK_MODULE = "prowler.providers.aws.services.transfer.transfer_server_fips_security_policy_enabled.transfer_server_fips_security_policy_enabled"

make_api_call = botocore.client.BaseClient._make_api_call


def mock_server_with_policy(security_policy_name):
    def _mock(self, operation_name, kwarg):
        if operation_name == "ListServers":
            return {"Servers": [{"Arn": SERVER_ARN, "ServerId": SERVER_ID}]}
        if operation_name == "DescribeServer":
            return {
                "Server": {
                    "Arn": SERVER_ARN,
                    "ServerId": SERVER_ID,
                    "Protocols": ["SFTP"],
                    "SecurityPolicyName": security_policy_name,
                }
            }
        return make_api_call(self, operation_name, kwarg)

    return _mock


def execute_check():
    from prowler.providers.aws.services.transfer.transfer_service import Transfer

    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(f"{CHECK_MODULE}.transfer_client", new=Transfer(aws_provider)),
    ):
        from prowler.providers.aws.services.transfer.transfer_server_fips_security_policy_enabled.transfer_server_fips_security_policy_enabled import (
            transfer_server_fips_security_policy_enabled,
        )

        return transfer_server_fips_security_policy_enabled().execute()


class Test_transfer_server_fips_security_policy_enabled:
    @mock_aws
    def test_no_servers(self):
        assert execute_check() == []

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_server_with_policy("TransferSecurityPolicy-FIPS-2025-03"),
    )
    @mock_aws
    def test_fips_policy(self):
        result = execute_check()

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Transfer Server {SERVER_ID} uses FIPS security policy TransferSecurityPolicy-FIPS-2025-03."
        )
        assert result[0].resource_id == SERVER_ID
        assert result[0].resource_arn == SERVER_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_server_with_policy("TransferSecurityPolicy-2024-01"),
    )
    @mock_aws
    def test_non_fips_policy(self):
        result = execute_check()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Transfer Server {SERVER_ID} uses security policy TransferSecurityPolicy-2024-01, which is not a FIPS security policy."
        )

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_server_with_policy(""),
    )
    @mock_aws
    def test_policy_not_retrieved(self):
        result = execute_check()

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"Transfer Server security policies could not be retrieved for {SERVER_ID}; verify the transfer:DescribeServer permission."
        )
        assert result[0].resource_id == AWS_ACCOUNT_NUMBER
        assert result[0].region == AWS_REGION_US_EAST_1
