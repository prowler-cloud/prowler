from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestEcsSecurityGroupRestrictSSHInternet:
    def test_security_group_open_to_internet_fails(self):
        ecs_client = mock.MagicMock()
        ecs_client.security_groups = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ecs.ecs_securitygroup_restrict_ssh_internet.ecs_securitygroup_restrict_ssh_internet.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_securitygroup_restrict_ssh_internet.ecs_securitygroup_restrict_ssh_internet import (
                ecs_securitygroup_restrict_ssh_internet,
            )
            from prowler.providers.alibabacloud.services.ecs.ecs_service import (
                SecurityGroup,
            )

            sg = SecurityGroup(
                id="sg-1",
                name="sg-open",
                region="cn-hangzhou",
                arn="arn:sg/sg-1",
                ingress_rules=[
                    {
                        "ip_protocol": "tcp",
                        "source_cidr_ip": "0.0.0.0/0",
                        "port_range": "22/22",
                        "policy": "accept",
                    }
                ],
            )
            ecs_client.security_groups = {sg.arn: sg}

            check = ecs_securitygroup_restrict_ssh_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "SSH port 22 open to the internet" in result[0].status_extended

    def test_security_group_restricted_passes(self):
        ecs_client = mock.MagicMock()
        ecs_client.security_groups = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ecs.ecs_securitygroup_restrict_ssh_internet.ecs_securitygroup_restrict_ssh_internet.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_securitygroup_restrict_ssh_internet.ecs_securitygroup_restrict_ssh_internet import (
                ecs_securitygroup_restrict_ssh_internet,
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
                        "port_range": "22/22",
                        "policy": "accept",
                    }
                ],
            )
            ecs_client.security_groups = {sg.arn: sg}

            check = ecs_securitygroup_restrict_ssh_internet()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "does not have SSH port 22 open" in result[0].status_extended
