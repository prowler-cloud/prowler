from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestVpcDefaultSecurityGroupRestrictsAllTraffic:
    def test_sg_with_open_ingress_fails(self):
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_default_security_group_restricts_all_traffic.vpc_default_security_group_restricts_all_traffic.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_default_security_group_restricts_all_traffic.vpc_default_security_group_restricts_all_traffic import (
                vpc_default_security_group_restricts_all_traffic,
            )
            from prowler.providers.huaweicloud.services.vpc.vpc_service import (
                SecurityGroups,
                SecurityGroupRule,
            )

            rule = SecurityGroupRule(
                id="rule-1",
                direction="ingress",
                protocol="tcp",
                ethertype="IPv4",
                remote_ip_prefix="0.0.0.0/0",
            )
            sg = SecurityGroups(
                id="sg-1",
                name="default",
                region="la-south-2",
                rules=[rule],
            )
            vpc_client.security_groups = {sg.id: sg}
            vpc_client.audited_account = "123456789012"

            check = vpc_default_security_group_restricts_all_traffic()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "ingress" in result[0].status_extended
            assert "0.0.0.0/0" in result[0].status_extended

    def test_sg_with_open_egress_fails(self):
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_default_security_group_restricts_all_traffic.vpc_default_security_group_restricts_all_traffic.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_default_security_group_restricts_all_traffic.vpc_default_security_group_restricts_all_traffic import (
                vpc_default_security_group_restricts_all_traffic,
            )
            from prowler.providers.huaweicloud.services.vpc.vpc_service import (
                SecurityGroups,
                SecurityGroupRule,
            )

            rule = SecurityGroupRule(
                id="rule-1",
                direction="egress",
                protocol="tcp",
                ethertype="IPv4",
                remote_ip_prefix="::/0",
            )
            sg = SecurityGroups(
                id="sg-1",
                name="default",
                region="la-south-2",
                rules=[rule],
            )
            vpc_client.security_groups = {sg.id: sg}
            vpc_client.audited_account = "123456789012"

            check = vpc_default_security_group_restricts_all_traffic()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "egress" in result[0].status_extended

    def test_sg_restricted_passes(self):
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_default_security_group_restricts_all_traffic.vpc_default_security_group_restricts_all_traffic.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_default_security_group_restricts_all_traffic.vpc_default_security_group_restricts_all_traffic import (
                vpc_default_security_group_restricts_all_traffic,
            )
            from prowler.providers.huaweicloud.services.vpc.vpc_service import (
                SecurityGroups,
                SecurityGroupRule,
            )

            rule = SecurityGroupRule(
                id="rule-1",
                direction="ingress",
                protocol="tcp",
                ethertype="IPv4",
                remote_ip_prefix="10.0.0.0/24",
            )
            sg = SecurityGroups(
                id="sg-1",
                name="default",
                region="la-south-2",
                rules=[rule],
            )
            vpc_client.security_groups = {sg.id: sg}
            vpc_client.audited_account = "123456789012"

            check = vpc_default_security_group_restricts_all_traffic()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "does not have any rule with open CIDR" in result[0].status_extended

    def test_sg_empty_name_skipped(self):
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_default_security_group_restricts_all_traffic.vpc_default_security_group_restricts_all_traffic.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_default_security_group_restricts_all_traffic.vpc_default_security_group_restricts_all_traffic import (
                vpc_default_security_group_restricts_all_traffic,
            )
            from prowler.providers.huaweicloud.services.vpc.vpc_service import (
                SecurityGroups,
            )

            sg = SecurityGroups(
                id="sg-1",
                name="",
                region="la-south-2",
                rules=[],
            )
            vpc_client.security_groups = {sg.id: sg}
            vpc_client.audited_account = "123456789012"

            check = vpc_default_security_group_restricts_all_traffic()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == ""

    def test_no_security_groups(self):
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_default_security_group_restricts_all_traffic.vpc_default_security_group_restricts_all_traffic.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_default_security_group_restricts_all_traffic.vpc_default_security_group_restricts_all_traffic import (
                vpc_default_security_group_restricts_all_traffic,
            )

            vpc_client.security_groups = {}
            vpc_client.audited_account = "123456789012"

            check = vpc_default_security_group_restricts_all_traffic()
            result = check.execute()

            assert len(result) == 0
