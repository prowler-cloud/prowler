from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestVpcSecurityGroupOpenIngress:
    def test_no_open_ingress_passes(self):
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_ingress.vpc_security_group_open_ingress.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_ingress.vpc_security_group_open_ingress import (
                vpc_security_group_open_ingress,
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
                        direction="ingress",
                        protocol="tcp",
                        ethertype="IPv4",
                        remote_ip_prefix="10.0.0.0/24",
                        port_range_min=22,
                        port_range_max=22,
                    ),
                ],
            )
            vpc_client.security_groups = {"sg-1": sg}
            vpc_client.audited_account = "123456789012"

            check = vpc_security_group_open_ingress()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "does not allow open ingress" in result[0].status_extended

    def test_open_ingress_ssh_fails(self):
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_ingress.vpc_security_group_open_ingress.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_ingress.vpc_security_group_open_ingress import (
                vpc_security_group_open_ingress,
            )
            from prowler.providers.huaweicloud.services.vpc.vpc_service import (
                SecurityGroupRule,
                SecurityGroups,
            )

            sg = SecurityGroups(
                id="sg-1",
                name="open-sg",
                region="la-south-2",
                vpc_id="vpc-1",
                rules=[
                    SecurityGroupRule(
                        id="rule-1",
                        direction="ingress",
                        protocol="tcp",
                        ethertype="IPv4",
                        remote_ip_prefix="0.0.0.0/0",
                        port_range_min=22,
                        port_range_max=22,
                    ),
                ],
            )
            vpc_client.security_groups = {"sg-1": sg}
            vpc_client.audited_account = "123456789012"

            check = vpc_security_group_open_ingress()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "22" in result[0].status_extended

    def test_open_ingress_rdp_fails(self):
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_ingress.vpc_security_group_open_ingress.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_ingress.vpc_security_group_open_ingress import (
                vpc_security_group_open_ingress,
            )
            from prowler.providers.huaweicloud.services.vpc.vpc_service import (
                SecurityGroupRule,
                SecurityGroups,
            )

            sg = SecurityGroups(
                id="sg-1",
                name="open-sg",
                region="la-south-2",
                vpc_id="vpc-1",
                rules=[
                    SecurityGroupRule(
                        id="rule-1",
                        direction="ingress",
                        protocol="tcp",
                        ethertype="IPv4",
                        remote_ip_prefix="::/0",
                        port_range_min=3389,
                        port_range_max=3389,
                    ),
                ],
            )
            vpc_client.security_groups = {"sg-1": sg}
            vpc_client.audited_account = "123456789012"

            check = vpc_security_group_open_ingress()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "3389" in result[0].status_extended

    def test_open_ingress_all_ports_fails(self):
        """port_range_min and port_range_max both None means 'all ports' in Huawei."""
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_ingress.vpc_security_group_open_ingress.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_ingress.vpc_security_group_open_ingress import (
                vpc_security_group_open_ingress,
            )
            from prowler.providers.huaweicloud.services.vpc.vpc_service import (
                SecurityGroupRule,
                SecurityGroups,
            )

            sg = SecurityGroups(
                id="sg-1",
                name="open-sg",
                region="la-south-2",
                vpc_id="vpc-1",
                rules=[
                    SecurityGroupRule(
                        id="rule-1",
                        direction="ingress",
                        protocol="",
                        ethertype="IPv4",
                        remote_ip_prefix="0.0.0.0/0",
                        port_range_min=None,
                        port_range_max=None,
                    ),
                ],
            )
            vpc_client.security_groups = {"sg-1": sg}
            vpc_client.audited_account = "123456789012"

            check = vpc_security_group_open_ingress()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            for port in ("22", "3389", "3306"):
                assert port in result[0].status_extended

    def test_open_ingress_wide_range_fails(self):
        """port range 1-65535 should behave like all-ports."""
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_ingress.vpc_security_group_open_ingress.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_ingress.vpc_security_group_open_ingress import (
                vpc_security_group_open_ingress,
            )
            from prowler.providers.huaweicloud.services.vpc.vpc_service import (
                SecurityGroupRule,
                SecurityGroups,
            )

            sg = SecurityGroups(
                id="sg-1",
                name="open-sg",
                region="la-south-2",
                vpc_id="vpc-1",
                rules=[
                    SecurityGroupRule(
                        id="rule-1",
                        direction="ingress",
                        protocol="tcp",
                        ethertype="IPv4",
                        remote_ip_prefix="0.0.0.0/0",
                        port_range_min=1,
                        port_range_max=65535,
                    ),
                ],
            )
            vpc_client.security_groups = {"sg-1": sg}
            vpc_client.audited_account = "123456789012"

            check = vpc_security_group_open_ingress()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "22" in result[0].status_extended

    def test_empty_source_fields_treated_as_open(self):
        """Empty remote_ip_prefix + empty remote_group_id = any source."""
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_ingress.vpc_security_group_open_ingress.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_ingress.vpc_security_group_open_ingress import (
                vpc_security_group_open_ingress,
            )
            from prowler.providers.huaweicloud.services.vpc.vpc_service import (
                SecurityGroupRule,
                SecurityGroups,
            )

            sg = SecurityGroups(
                id="sg-1",
                name="open-sg",
                region="eu-west-101",
                vpc_id="vpc-1",
                rules=[
                    SecurityGroupRule(
                        id="rule-1",
                        direction="ingress",
                        protocol="",
                        ethertype="IPv4",
                        remote_ip_prefix="",
                        remote_group_id="",
                        port_range_min=22,
                        port_range_max=22,
                    ),
                ],
            )
            vpc_client.security_groups = {"sg-1": sg}
            vpc_client.audited_account = "123456789012"

            check = vpc_security_group_open_ingress()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "22" in result[0].status_extended

    def test_remote_group_reference_not_flagged(self):
        """Empty remote_ip_prefix but a remote_group_id is NOT open."""
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_ingress.vpc_security_group_open_ingress.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_ingress.vpc_security_group_open_ingress import (
                vpc_security_group_open_ingress,
            )
            from prowler.providers.huaweicloud.services.vpc.vpc_service import (
                SecurityGroupRule,
                SecurityGroups,
            )

            sg = SecurityGroups(
                id="sg-1",
                name="app-sg",
                region="la-south-2",
                vpc_id="vpc-1",
                rules=[
                    SecurityGroupRule(
                        id="rule-1",
                        direction="ingress",
                        protocol="tcp",
                        ethertype="IPv4",
                        remote_ip_prefix="",
                        remote_group_id="sg-2",
                        port_range_min=22,
                        port_range_max=22,
                    ),
                ],
            )
            vpc_client.security_groups = {"sg-1": sg}
            vpc_client.audited_account = "123456789012"

            check = vpc_security_group_open_ingress()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_no_security_groups(self):
        vpc_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_ingress.vpc_security_group_open_ingress.vpc_client",
                new=vpc_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.vpc.vpc_security_group_open_ingress.vpc_security_group_open_ingress import (
                vpc_security_group_open_ingress,
            )

            vpc_client.security_groups = {}
            vpc_client.audited_account = "123456789012"

            check = vpc_security_group_open_ingress()
            result = check.execute()

            assert len(result) == 0
