from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestVPCFlowLogsEnabled:
    def test_vpc_without_flow_logs_fails(self):
        vpc_client = mock.MagicMock()
        vpc_client.audited_account = "1234567890"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled import (
                vpc_flow_logs_enabled,
            )
            from prowler.providers.alibabacloud.services.vpc.vpc_service import VPCs

            vpc = VPCs(
                id="vpc-1",
                name="vpc-1",
                region="cn-hangzhou",
                cidr_block="10.0.0.0/16",
                flow_log_enabled=False,
            )
            vpc_client.vpcs = {vpc.id: vpc}

            check = vpc_flow_logs_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not have flow logs enabled" in result[0].status_extended

    def test_vpc_with_flow_logs_passes(self):
        vpc_client = mock.MagicMock()
        vpc_client.audited_account = "1234567890"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled import (
                vpc_flow_logs_enabled,
            )
            from prowler.providers.alibabacloud.services.vpc.vpc_service import VPCs

            vpc = VPCs(
                id="vpc-2",
                name="vpc-2",
                region="cn-hangzhou",
                cidr_block="10.1.0.0/16",
                flow_log_enabled=True,
            )
            vpc_client.vpcs = {vpc.id: vpc}

            check = vpc_flow_logs_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "has flow logs enabled" in result[0].status_extended
