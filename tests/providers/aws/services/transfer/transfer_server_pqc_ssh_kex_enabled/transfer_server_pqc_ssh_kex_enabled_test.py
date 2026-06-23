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


def _make_describe_server_mock(security_policy_name: str):
    def _mock(self, operation_name, kwarg):
        if operation_name == "ListServers":
            return {
                "Servers": [
                    {
                        "Arn": SERVER_ARN,
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
                    "SecurityPolicyName": security_policy_name,
                }
            }
        return make_api_call(self, operation_name, kwarg)

    return _mock


mock_pqc = _make_describe_server_mock("TransferSecurityPolicy-2025-03")
mock_fips_pqc = _make_describe_server_mock("TransferSecurityPolicy-FIPS-2025-03")
mock_classical = _make_describe_server_mock("TransferSecurityPolicy-2024-01")
mock_no_policy = _make_describe_server_mock("")


class Test_transfer_server_pqc_ssh_kex_enabled:
    @mock_aws
    def test_no_servers(self):
        from prowler.providers.aws.services.transfer.transfer_service import Transfer

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.transfer.transfer_server_pqc_ssh_kex_enabled.transfer_server_pqc_ssh_kex_enabled.transfer_client",
                new=Transfer(aws_provider),
            ):
                from prowler.providers.aws.services.transfer.transfer_server_pqc_ssh_kex_enabled.transfer_server_pqc_ssh_kex_enabled import (
                    transfer_server_pqc_ssh_kex_enabled,
                )

                check = transfer_server_pqc_ssh_kex_enabled()
                result = check.execute()

                assert len(result) == 0

    @patch("botocore.client.BaseClient._make_api_call", new=mock_pqc)
    @mock_aws
    def test_pq_policy(self):
        from prowler.providers.aws.services.transfer.transfer_service import Transfer

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.transfer.transfer_server_pqc_ssh_kex_enabled.transfer_server_pqc_ssh_kex_enabled.transfer_client",
                new=Transfer(aws_provider),
            ):
                from prowler.providers.aws.services.transfer.transfer_server_pqc_ssh_kex_enabled.transfer_server_pqc_ssh_kex_enabled import (
                    transfer_server_pqc_ssh_kex_enabled,
                )

                check = transfer_server_pqc_ssh_kex_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert "TransferSecurityPolicy-2025-03" in result[0].status_extended
                assert result[0].resource_id == SERVER_ID
                assert result[0].resource_arn == SERVER_ARN
                assert result[0].region == AWS_REGION_US_EAST_1

    @patch("botocore.client.BaseClient._make_api_call", new=mock_fips_pqc)
    @mock_aws
    def test_fips_pq_policy(self):
        from prowler.providers.aws.services.transfer.transfer_service import Transfer

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.transfer.transfer_server_pqc_ssh_kex_enabled.transfer_server_pqc_ssh_kex_enabled.transfer_client",
                new=Transfer(aws_provider),
            ):
                from prowler.providers.aws.services.transfer.transfer_server_pqc_ssh_kex_enabled.transfer_server_pqc_ssh_kex_enabled import (
                    transfer_server_pqc_ssh_kex_enabled,
                )

                check = transfer_server_pqc_ssh_kex_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert "FIPS-2025-03" in result[0].status_extended

    @patch("botocore.client.BaseClient._make_api_call", new=mock_classical)
    @mock_aws
    def test_classical_policy(self):
        from prowler.providers.aws.services.transfer.transfer_service import Transfer

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.transfer.transfer_server_pqc_ssh_kex_enabled.transfer_server_pqc_ssh_kex_enabled.transfer_client",
                new=Transfer(aws_provider),
            ):
                from prowler.providers.aws.services.transfer.transfer_server_pqc_ssh_kex_enabled.transfer_server_pqc_ssh_kex_enabled import (
                    transfer_server_pqc_ssh_kex_enabled,
                )

                check = transfer_server_pqc_ssh_kex_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert "TransferSecurityPolicy-2024-01" in result[0].status_extended
                assert "does not enable post-quantum" in result[0].status_extended

    @patch("botocore.client.BaseClient._make_api_call", new=mock_no_policy)
    @mock_aws
    def test_missing_policy(self):
        from prowler.providers.aws.services.transfer.transfer_service import Transfer

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.transfer.transfer_server_pqc_ssh_kex_enabled.transfer_server_pqc_ssh_kex_enabled.transfer_client",
                new=Transfer(aws_provider),
            ):
                from prowler.providers.aws.services.transfer.transfer_server_pqc_ssh_kex_enabled.transfer_server_pqc_ssh_kex_enabled import (
                    transfer_server_pqc_ssh_kex_enabled,
                )

                check = transfer_server_pqc_ssh_kex_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert "<none>" in result[0].status_extended

    @patch("botocore.client.BaseClient._make_api_call", new=mock_classical)
    @mock_aws
    def test_configurable_allowlist(self):
        from prowler.providers.aws.services.transfer.transfer_service import Transfer

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1],
            audit_config={
                "transfer_pqc_ssh_allowed_policies": [
                    "TransferSecurityPolicy-2025-03",
                    "TransferSecurityPolicy-2024-01",
                ]
            },
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.transfer.transfer_server_pqc_ssh_kex_enabled.transfer_server_pqc_ssh_kex_enabled.transfer_client",
                new=Transfer(aws_provider),
            ):
                from prowler.providers.aws.services.transfer.transfer_server_pqc_ssh_kex_enabled.transfer_server_pqc_ssh_kex_enabled import (
                    transfer_server_pqc_ssh_kex_enabled,
                )

                check = transfer_server_pqc_ssh_kex_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
