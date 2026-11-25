from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestEcsSecurityGroupRestrictRdpInternet:
    def test_rdp_open_fails(self):
        ecs_client = mock.MagicMock()
        ecs_client.security_groups = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ecs.ecs_securitygroup_restrict_rdp_internet.ecs_securitygroup_restrict_rdp_internet.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_securitygroup_restrict_rdp_internet.ecs_securitygroup_restrict_rdp_internet import (
                ecs_securitygroup_restrict_rdp_internet,
            )
            from prowler.providers.alibabacloud.services.ecs.ecs_service import (
                SecurityGroup,
            )

            sg = SecurityGroup(
                id="sg-1",
                name="sg-rdp",
                region="cn-hangzhou",
                arn="arn:sg/sg-1",
                ingress_rules=[
                    {
                        "ip_protocol": "tcp",
                        "source_cidr_ip": "0.0.0.0/0",
                        "port_range": "3389/3389",
                        "policy": "Accept",
                    }
                ],
            )
            ecs_client.security_groups = {sg.arn: sg}

            check = ecs_securitygroup_restrict_rdp_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_rdp_open_to_ipv6_internet_fails(self):
        ecs_client = mock.MagicMock()
        ecs_client.security_groups = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ecs.ecs_securitygroup_restrict_rdp_internet.ecs_securitygroup_restrict_rdp_internet.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_securitygroup_restrict_rdp_internet.ecs_securitygroup_restrict_rdp_internet import (
                ecs_securitygroup_restrict_rdp_internet,
            )
            from prowler.providers.alibabacloud.services.ecs.ecs_service import (
                SecurityGroup,
            )

            sg = SecurityGroup(
                id="sg-ipv6",
                name="sg-rdp-ipv6",
                region="cn-hangzhou",
                arn="arn:sg/sg-ipv6",
                ingress_rules=[
                    {
                        "ip_protocol": "tcp",
                        "source_cidr_ip": "",
                        "ipv6_source_cidr_ip": "::/0",
                        "port_range": "3389/3389",
                        "policy": "Accept",
                    }
                ],
            )
            ecs_client.security_groups = {sg.arn: sg}

            check = ecs_securitygroup_restrict_rdp_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "(::/0)" in result[0].status_extended

    def test_rdp_restricted_passes(self):
        ecs_client = mock.MagicMock()
        ecs_client.security_groups = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ecs.ecs_securitygroup_restrict_rdp_internet.ecs_securitygroup_restrict_rdp_internet.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_securitygroup_restrict_rdp_internet.ecs_securitygroup_restrict_rdp_internet import (
                ecs_securitygroup_restrict_rdp_internet,
            )
            from prowler.providers.alibabacloud.services.ecs.ecs_service import (
                SecurityGroup,
            )

            sg = SecurityGroup(
                id="sg-2",
                name="sg-restricted",
                region="cn-hangzhou",
                arn="arn:sg/sg-2",
                ingress_rules=[
                    {
                        "ip_protocol": "tcp",
                        "source_cidr_ip": "10.0.0.0/24",
                        "port_range": "3389/3389",
                        "policy": "Accept",
                    }
                ],
            )
            ecs_client.security_groups = {sg.arn: sg}

            check = ecs_securitygroup_restrict_rdp_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
