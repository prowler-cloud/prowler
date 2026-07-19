from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

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

    def test_describe_security_groups_extracts_ipv6_ingress_source(self):
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

            security_group = SimpleNamespace(
                security_group_id="sg-ipv6",
                security_group_name="ipv6-group",
                vpc_id="vpc-1",
                description="IPv6 test group",
            )
            ingress_rule = SimpleNamespace(
                port_range="22/22",
                source_cidr_ip="",
                ipv_6source_cidr_ip="::/0",
                ip_protocol="tcp",
                policy="Accept",
                priority=5,
            )
            list_response = SimpleNamespace(
                body=SimpleNamespace(
                    security_groups=SimpleNamespace(security_group=[security_group]),
                    total_count=1,
                )
            )

            regional_client = MagicMock()
            regional_client.region = "cn-hangzhou"
            regional_client.describe_security_groups.return_value = list_response

            def describe_rules(request):
                rules = [ingress_rule] if request.direction == "ingress" else []
                return SimpleNamespace(
                    body=SimpleNamespace(permissions=SimpleNamespace(permission=rules))
                )

            regional_client.describe_security_group_attribute.side_effect = (
                describe_rules
            )

            ecs_client._describe_security_groups(regional_client)

            stored_group = next(iter(ecs_client.security_groups.values()))
            assert stored_group.ingress_rules == [
                {
                    "port_range": "22/22",
                    "source_cidr_ip": "",
                    "ipv_6source_cidr_ip": "::/0",
                    "ip_protocol": "tcp",
                    "policy": "Accept",
                    "priority": 5,
                }
            ]
            assert stored_group.ingress_rules_complete is True

    @pytest.mark.parametrize(
        "ingress_response,expected_complete",
        [
            (RuntimeError("rule fetch failed"), False),
            (None, False),
            (SimpleNamespace(body=None), False),
            (SimpleNamespace(body=SimpleNamespace(permissions=None)), False),
            (
                SimpleNamespace(body=SimpleNamespace(permissions=SimpleNamespace())),
                False,
            ),
            (
                SimpleNamespace(
                    body=SimpleNamespace(permissions=SimpleNamespace(permission=None))
                ),
                False,
            ),
            (
                SimpleNamespace(
                    body=SimpleNamespace(permissions=SimpleNamespace(permission=[]))
                ),
                True,
            ),
        ],
    )
    def test_describe_security_groups_tracks_ingress_completeness(
        self, ingress_response, expected_complete
    ):
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
            security_group = SimpleNamespace(
                security_group_id="sg-completeness",
                security_group_name="completeness-group",
                vpc_id="vpc-1",
                description="Completeness test group",
            )
            regional_client = MagicMock()
            regional_client.region = "cn-hangzhou"
            regional_client.describe_security_groups.return_value = SimpleNamespace(
                body=SimpleNamespace(
                    security_groups=SimpleNamespace(security_group=[security_group]),
                    total_count=1,
                )
            )
            empty_rules_response = SimpleNamespace(
                body=SimpleNamespace(permissions=SimpleNamespace(permission=[]))
            )

            def describe_rules(request):
                if request.direction == "egress":
                    return empty_rules_response
                if isinstance(ingress_response, Exception):
                    raise ingress_response
                return ingress_response

            regional_client.describe_security_group_attribute.side_effect = (
                describe_rules
            )

            ecs_client._describe_security_groups(regional_client)

            stored_group = next(iter(ecs_client.security_groups.values()))
            assert stored_group.ingress_rules_complete is expected_complete
            assert stored_group.ingress_rules == []
