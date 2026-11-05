from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestVpcSecurityGroupOpenEgress:
    def test_no_open_egress_passes(self):
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_egress.vpc_security_group_open_egress.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_egress.vpc_security_group_open_egress import (
                vpc_security_group_open_egress,
            )
            from prowler.providers.huaweicloud.services.vpc.vpc_service import (
                SecurityGroupRule,
                SecurityGroups,
            )

            sg = SecurityGroups(
                id="sg-1",
                name="safe-sg",
                region="la-south-2",
                vpc_id="vpc-1",
                rules=[
                    SecurityGroupRule(
                        id="rule-1",
                        direction="egress",
                        protocol="tcp",
                        ethertype="IPv4",
                        remote_ip_prefix="10.0.0.0/24",
                        port_range_min=443,
                        port_range_max=443,
                    ),
                    SecurityGroupRule(
                        id="deny-rule",
                        direction="egress",
                        action="deny",
                        protocol="",
                        ethertype="IPv4",
                        remote_ip_prefix="",
                    ),
                    SecurityGroupRule(
                        id="address-group-rule",
                        direction="egress",
                        action="allow",
                        protocol="",
                        ethertype="IPv4",
                        remote_ip_prefix="",
                        remote_address_group_id="address-group-1",
                    ),
                ],
            )
            vpc_client.security_groups = {"sg-1": sg}
            vpc_client.audited_account = "123456789012"

            check = vpc_security_group_open_egress()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "Security group safe-sg (sg-1) does not allow open egress to "
                "the internet."
            )
            assert result[0].resource_id == "sg-1"
            assert result[0].resource_name == "safe-sg"
            assert result[0].resource_arn == (
                "huaweicloud:vpc:la-south-2:123456789012:security-group/sg-1"
            )
            assert result[0].region == "la-south-2"

    def test_open_egress_ipv4_fails(self):
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_egress.vpc_security_group_open_egress.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_egress.vpc_security_group_open_egress import (
                vpc_security_group_open_egress,
            )
            from prowler.providers.huaweicloud.services.vpc.vpc_service import (
                SecurityGroupRule,
                SecurityGroups,
            )

            sg = SecurityGroups(
                id="sg-1",
                name="open-egress-sg",
                region="la-south-2",
                vpc_id="vpc-1",
                rules=[
                    SecurityGroupRule(
                        id="rule-1",
                        direction="egress",
                        protocol="tcp",
                        ethertype="IPv4",
                        remote_ip_prefix="0.0.0.0/0",
                        port_range_min=80,
                        port_range_max=80,
                    ),
                ],
            )
            vpc_client.security_groups = {"sg-1": sg}
            vpc_client.audited_account = "123456789012"

            check = vpc_security_group_open_egress()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "Security group open-egress-sg (sg-1) allows open egress "
                "(0.0.0.0/0) to the internet."
            )
            assert result[0].resource_id == "sg-1"
            assert result[0].resource_name == "open-egress-sg"
            assert result[0].resource_arn == (
                "huaweicloud:vpc:la-south-2:123456789012:security-group/sg-1"
            )
            assert result[0].region == "la-south-2"

    def test_open_egress_ipv6_fails(self):
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_egress.vpc_security_group_open_egress.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_egress.vpc_security_group_open_egress import (
                vpc_security_group_open_egress,
            )
            from prowler.providers.huaweicloud.services.vpc.vpc_service import (
                SecurityGroupRule,
                SecurityGroups,
            )

            sg = SecurityGroups(
                id="sg-1",
                name="open-egress-sg-ipv6",
                region="la-south-2",
                vpc_id="vpc-1",
                rules=[
                    SecurityGroupRule(
                        id="rule-1",
                        direction="egress",
                        protocol="tcp",
                        ethertype="IPv6",
                        remote_ip_prefix="::/0",
                        port_range_min=443,
                        port_range_max=443,
                    ),
                ],
            )
            vpc_client.security_groups = {"sg-1": sg}
            vpc_client.audited_account = "123456789012"

            check = vpc_security_group_open_egress()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "Security group open-egress-sg-ipv6 (sg-1) allows open egress "
                "(::/0) to the internet."
            )
            assert result[0].resource_id == "sg-1"
            assert result[0].resource_name == "open-egress-sg-ipv6"
            assert result[0].resource_arn == (
                "huaweicloud:vpc:la-south-2:123456789012:security-group/sg-1"
            )
            assert result[0].region == "la-south-2"

    def test_open_egress_with_empty_destination_fails(self):
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_egress.vpc_security_group_open_egress.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_egress.vpc_security_group_open_egress import (
                vpc_security_group_open_egress,
            )
            from prowler.providers.huaweicloud.services.vpc.vpc_service import (
                SecurityGroupRule,
                SecurityGroups,
            )

            sg = SecurityGroups(
                id="sg-1",
                name="open-egress-sg-empty-destination",
                region="la-south-2",
                vpc_id="vpc-1",
                rules=[
                    SecurityGroupRule(
                        id="rule-1",
                        direction="egress",
                        action="allow",
                        protocol="",
                        ethertype="IPv4",
                        remote_ip_prefix="",
                        remote_address_group_id="",
                    ),
                ],
            )
            vpc_client.security_groups = {"sg-1": sg}
            vpc_client.audited_account = "123456789012"

            check = vpc_security_group_open_egress()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "Security group open-egress-sg-empty-destination (sg-1) allows "
                "open egress (all destinations) to the internet."
            )
            assert result[0].resource_id == "sg-1"
            assert result[0].resource_name == "open-egress-sg-empty-destination"
            assert result[0].resource_arn == (
                "huaweicloud:vpc:la-south-2:123456789012:security-group/sg-1"
            )
            assert result[0].region == "la-south-2"

    def test_no_security_groups(self):
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_egress.vpc_security_group_open_egress.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_egress.vpc_security_group_open_egress import (
                vpc_security_group_open_egress,
            )

            vpc_client.security_groups = {}
            vpc_client.audited_account = "123456789012"

            check = vpc_security_group_open_egress()
            result = check.execute()

            assert len(result) == 0
