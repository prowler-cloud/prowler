from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    ALIBABACLOUD_REGION,
    set_mocked_alibabacloud_provider,
)


class Test_vpc_flow_logs_enabled:
    def test_no_vpcs(self):
        vpc_client = mock.MagicMock
        vpc_client.vpcs = {}
        vpc_client.flow_logs = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled.vpc_client",
            new=vpc_client,
        ):
            from prowler.providers.alibabacloud.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled import (
                vpc_flow_logs_enabled,
            )

            check = vpc_flow_logs_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_vpc_with_flow_logs(self):
        vpc_client = mock.MagicMock
        vpc_id = "vpc-test123"
        vpc_arn = f"acs:vpc:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:vpc/{vpc_id}"
        flow_log_id = "fl-test123"
        flow_log_arn = f"acs:vpc:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:flowlog/{flow_log_id}"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled.vpc_client",
            new=vpc_client,
        ):
            from prowler.providers.alibabacloud.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled import (
                vpc_flow_logs_enabled,
            )
            from prowler.providers.alibabacloud.services.vpc.vpc_service import (
                FlowLog,
                VPC,
            )

            vpc_client.vpcs = {
                vpc_arn: VPC(
                    vpc_id=vpc_id,
                    vpc_name="test-vpc",
                    arn=vpc_arn,
                    region=ALIBABACLOUD_REGION,
                    cidr_block="172.16.0.0/12",
                    status="Available",
                    is_default=False,
                )
            }
            vpc_client.flow_logs = {
                flow_log_arn: FlowLog(
                    flow_log_id=flow_log_id,
                    flow_log_name="test-flow-log",
                    arn=flow_log_arn,
                    region=ALIBABACLOUD_REGION,
                    resource_type="VPC",
                    resource_id=vpc_id,
                    status="Active",
                )
            }
            vpc_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = vpc_flow_logs_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == vpc_id
            assert result[0].resource_arn == vpc_arn
            assert result[0].region == ALIBABACLOUD_REGION

    def test_vpc_without_flow_logs(self):
        vpc_client = mock.MagicMock
        vpc_id = "vpc-test456"
        vpc_arn = f"acs:vpc:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:vpc/{vpc_id}"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled.vpc_client",
            new=vpc_client,
        ):
            from prowler.providers.alibabacloud.services.vpc.vpc_flow_logs_enabled.vpc_flow_logs_enabled import (
                vpc_flow_logs_enabled,
            )
            from prowler.providers.alibabacloud.services.vpc.vpc_service import VPC

            vpc_client.vpcs = {
                vpc_arn: VPC(
                    vpc_id=vpc_id,
                    vpc_name="test-vpc-no-logs",
                    arn=vpc_arn,
                    region=ALIBABACLOUD_REGION,
                    cidr_block="172.16.0.0/12",
                    status="Available",
                    is_default=False,
                )
            }
            vpc_client.flow_logs = {}
            vpc_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = vpc_flow_logs_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == vpc_id
            assert result[0].resource_arn == vpc_arn
            assert result[0].region == ALIBABACLOUD_REGION
