from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestVpcSecurityGroupAllProtocolsOpen:
    def test_security_group_all_protocols_open_fails(self):
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_security_group_all_protocols_open.vpc_security_group_all_protocols_open.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_security_group_all_protocols_open.vpc_security_group_all_protocols_open import (
                vpc_security_group_all_protocols_open,
            )
            from prowler.providers.huaweicloud.services.vpc.vpc_service import (
                SecurityGroupRule,
                SecurityGroups,
            )

            sg = SecurityGroups(
                id="sg-1",
                name="open-sg",
                region="la-south-2",
                rules=[
                    SecurityGroupRule(
                        id="rule-1",
                        direction="ingress",
                        protocol="",
                        ethertype="IPv4",
                        remote_ip_prefix="0.0.0.0/0",
                        port_range_min=None,
                        port_range_max=None,
                    )
                ],
            )
            vpc_client.security_groups = {sg.id: sg}
            vpc_client.audited_account = "123456789012"

            check = vpc_security_group_all_protocols_open()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "sg-1"
            assert "all ports/protocols" in result[0].status_extended

    def test_security_group_restricted_passes(self):
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_security_group_all_protocols_open.vpc_security_group_all_protocols_open.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_security_group_all_protocols_open.vpc_security_group_all_protocols_open import (
                vpc_security_group_all_protocols_open,
            )
            from prowler.providers.huaweicloud.services.vpc.vpc_service import (
                SecurityGroupRule,
                SecurityGroups,
            )

            sg = SecurityGroups(
                id="sg-1",
                name="restricted-sg",
                region="la-south-2",
                rules=[
                    SecurityGroupRule(
                        id="rule-1",
                        direction="ingress",
                        protocol="tcp",
                        ethertype="IPv4",
                        remote_ip_prefix="0.0.0.0/0",
                        port_range_min=443,
                        port_range_max=443,
                    ),
                    # All-protocols rule but not from a public CIDR -> must not trigger
                    SecurityGroupRule(
                        id="rule-2",
                        direction="ingress",
                        protocol="",
                        ethertype="IPv4",
                        remote_ip_prefix="192.168.0.0/16",
                        port_range_min=None,
                        port_range_max=None,
                    ),
                    # All-protocols rule from public CIDR but egress -> must not trigger
                    SecurityGroupRule(
                        id="rule-3",
                        direction="egress",
                        protocol="",
                        ethertype="IPv4",
                        remote_ip_prefix="0.0.0.0/0",
                        port_range_min=None,
                        port_range_max=None,
                    ),
                ],
            )
            vpc_client.security_groups = {sg.id: sg}
            vpc_client.audited_account = "123456789012"

            check = vpc_security_group_all_protocols_open()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "does not allow ingress from 0.0.0.0/0" in result[0].status_extended

    def test_no_security_groups(self):
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_security_group_all_protocols_open.vpc_security_group_all_protocols_open.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_security_group_all_protocols_open.vpc_security_group_all_protocols_open import (
                vpc_security_group_all_protocols_open,
            )

            vpc_client.security_groups = {}
            vpc_client.audited_account = "123456789012"

            check = vpc_security_group_all_protocols_open()
            result = check.execute()

            assert len(result) == 0
