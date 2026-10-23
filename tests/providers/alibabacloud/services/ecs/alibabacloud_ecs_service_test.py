from unittest.mock import patch

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestECSService:
    def test_service(self):
        alibabacloud_provider = set_mocked_alibabacloud_provider()

        with patch(
            "prowler.providers.alibabacloud.services.ecs.ecs_service.ECS.__init__",
            return_value=None,
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_service import ECS

            ecs_client = ECS(alibabacloud_provider)
            ecs_client.service = "ecs"
            ecs_client.provider = alibabacloud_provider
            ecs_client.regional_clients = {}

            assert ecs_client.service == "ecs"
            assert ecs_client.provider == alibabacloud_provider

    def test_describe_security_groups_keeps_ipv6_sources(self):
        from types import SimpleNamespace
        from unittest.mock import MagicMock

        from alibabacloud_ecs20140526 import models as ecs_models

        alibabacloud_provider = set_mocked_alibabacloud_provider()

        with patch(
            "prowler.providers.alibabacloud.services.ecs.ecs_service.ECS.__init__",
            return_value=None,
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_service import ECS

            ecs_client = ECS(alibabacloud_provider)
            ecs_client.audit_resources = []
            ecs_client.audited_account = "1234567890"
            ecs_client.security_groups = {}

            regional_client = MagicMock()
            regional_client.region = "cn-hangzhou"
            regional_client.describe_security_groups.return_value = SimpleNamespace(
                body=SimpleNamespace(
                    total_count=1,
                    security_groups=SimpleNamespace(
                        security_group=[
                            SimpleNamespace(
                                security_group_id="sg-ipv6",
                                security_group_name="sg-ipv6",
                            )
                        ]
                    ),
                )
            )
            permission = ecs_models.DescribeSecurityGroupAttributeResponseBodyPermissionsPermission(
                ip_protocol="TCP",
                port_range="22/22",
                policy="Accept",
                ipv_6source_cidr_ip="::/0",
                ipv_6dest_cidr_ip="::/0",
            )
            regional_client.describe_security_group_attribute.return_value = (
                SimpleNamespace(
                    body=SimpleNamespace(
                        permissions=SimpleNamespace(permission=[permission])
                    )
                )
            )

            ecs_client._describe_security_groups(regional_client)

            security_group = ecs_client.security_groups[
                "acs:ecs:cn-hangzhou:1234567890:security-group/sg-ipv6"
            ]
            assert security_group.ingress_rules[0]["ipv6_source_cidr_ip"] == "::/0"
            assert security_group.egress_rules[0]["ipv6_dest_cidr_ip"] == "::/0"
