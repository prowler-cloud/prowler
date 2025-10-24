from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    ALIBABACLOUD_REGION,
    set_mocked_alibabacloud_provider,
)


class Test_vpc_default_vpc_in_use:
    def test_no_vpcs(self):
        vpc_client = mock.MagicMock
        vpc_client.vpcs = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.vpc.vpc_default_vpc_in_use.vpc_default_vpc_in_use.vpc_client",
            new=vpc_client,
        ):
            from prowler.providers.alibabacloud.services.vpc.vpc_default_vpc_in_use.vpc_default_vpc_in_use import (
                vpc_default_vpc_in_use,
            )

            check = vpc_default_vpc_in_use()
            result = check.execute()
            assert len(result) == 0

    def test_vpc_not_default(self):
        vpc_client = mock.MagicMock
        vpc_id = "vpc-custom123"
        vpc_arn = f"acs:vpc:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:vpc/{vpc_id}"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.vpc.vpc_default_vpc_in_use.vpc_default_vpc_in_use.vpc_client",
            new=vpc_client,
        ):
            from prowler.providers.alibabacloud.services.vpc.vpc_default_vpc_in_use.vpc_default_vpc_in_use import (
                vpc_default_vpc_in_use,
            )
            from prowler.providers.alibabacloud.services.vpc.vpc_service import VPC

            vpc_client.vpcs = {
                vpc_arn: VPC(
                    vpc_id=vpc_id,
                    vpc_name="custom-vpc",
                    arn=vpc_arn,
                    region=ALIBABACLOUD_REGION,
                    cidr_block="172.16.0.0/12",
                    status="Available",
                    is_default=False,
                )
            }
            vpc_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = vpc_default_vpc_in_use()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == vpc_id
            assert result[0].resource_arn == vpc_arn
            assert result[0].region == ALIBABACLOUD_REGION

    def test_vpc_is_default(self):
        vpc_client = mock.MagicMock
        vpc_id = "vpc-default123"
        vpc_arn = f"acs:vpc:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:vpc/{vpc_id}"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.vpc.vpc_default_vpc_in_use.vpc_default_vpc_in_use.vpc_client",
            new=vpc_client,
        ):
            from prowler.providers.alibabacloud.services.vpc.vpc_default_vpc_in_use.vpc_default_vpc_in_use import (
                vpc_default_vpc_in_use,
            )
            from prowler.providers.alibabacloud.services.vpc.vpc_service import VPC

            vpc_client.vpcs = {
                vpc_arn: VPC(
                    vpc_id=vpc_id,
                    vpc_name="default-vpc",
                    arn=vpc_arn,
                    region=ALIBABACLOUD_REGION,
                    cidr_block="172.16.0.0/12",
                    status="Available",
                    is_default=True,
                )
            }
            vpc_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = vpc_default_vpc_in_use()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == vpc_id
            assert result[0].resource_arn == vpc_arn
            assert result[0].region == ALIBABACLOUD_REGION
