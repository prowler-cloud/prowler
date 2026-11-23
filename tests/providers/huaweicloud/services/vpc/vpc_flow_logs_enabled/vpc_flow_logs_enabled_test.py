from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestVPCFlowLogsEnabled:
    def test_no_resources(self):
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled import (
                vpc_flow_logs_enabled,
            )

            vpc_client.vpcs = {}
            vpc_client.flow_logs = []
            vpc_client.audited_account = "123456789012"

            result = vpc_flow_logs_enabled().execute()
            assert len(result) == 0

    def test_vpc_with_active_flow_log_passes(self):
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled import (
                vpc_flow_logs_enabled,
            )
            from prowler.providers.huaweicloud.services.vpc.vpc_service import (
                FlowLog,
                VPCs,
            )

            vpc_client.vpcs = {
                "vpc-1": VPCs(
                    id="vpc-1",
                    name="prod-vpc",
                    region="cn-north-4",
                    cidr="10.0.0.0/16",
                )
            }
            vpc_client.flow_logs = [
                FlowLog(
                    id="fl-1",
                    name="prod-flow-log",
                    resource_type="vpc",
                    resource_id="vpc-1",
                    status="ACTIVE",
                    admin_state=True,
                    region="cn-north-4",
                )
            ]
            vpc_client.audited_account = "123456789012"

            result = vpc_flow_logs_enabled().execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "has flow logs enabled" in result[0].status_extended

    def test_vpc_without_flow_log_fails(self):
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled import (
                vpc_flow_logs_enabled,
            )
            from prowler.providers.huaweicloud.services.vpc.vpc_service import VPCs

            vpc_client.vpcs = {
                "vpc-2": VPCs(
                    id="vpc-2",
                    name="dev-vpc",
                    region="cn-north-4",
                    cidr="10.1.0.0/16",
                )
            }
            vpc_client.flow_logs = []
            vpc_client.audited_account = "123456789012"

            result = vpc_flow_logs_enabled().execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not have flow logs enabled" in result[0].status_extended

    def test_failed_region_skipped(self):
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled import (
                vpc_flow_logs_enabled,
            )
            from prowler.providers.huaweicloud.services.vpc.vpc_service import VPCs

            vpc_client.vpcs = {
                "vpc-3": VPCs(
                    id="vpc-3",
                    name="errored-region-vpc",
                    region="cn-north-4",
                    cidr="10.2.0.0/16",
                )
            }
            vpc_client.flow_logs = []
            vpc_client.flow_logs_failed_regions = {"cn-north-4"}
            vpc_client.audited_account = "123456789012"

            result = vpc_flow_logs_enabled().execute()
            assert len(result) == 0
