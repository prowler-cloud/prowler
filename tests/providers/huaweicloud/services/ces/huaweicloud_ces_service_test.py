from types import SimpleNamespace
from unittest import mock

import pytest

from prowler.providers.huaweicloud.services.ces.ces_service import CES
from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


def _alarm(alarm_id, name, enabled, policies=None, resources=None):
    return SimpleNamespace(
        alarm_id=alarm_id,
        name=name,
        enabled=enabled,
        policies=policies or [],
        resources=resources or [],
    )


class TestCESService:
    def test_list_alarm_rules_paginates_and_preserves_rule_details(self):
        policy = SimpleNamespace(metric_name="cpu_util", period=300)
        resources = [
            SimpleNamespace(
                resource_group_id="",
                resource_group_name="",
                dimensions=[
                    SimpleNamespace(name="instance_id", value="instance-1"),
                    SimpleNamespace(name="disk", value="vda"),
                ],
            )
        ]
        client = mock.MagicMock()
        client.list_alarm_rules.side_effect = [
            SimpleNamespace(alarms=[_alarm("alarm-1", "enabled-rule", True)], count=2),
            SimpleNamespace(
                alarms=[
                    _alarm(
                        "alarm-2",
                        "disabled-rule",
                        False,
                        policies=[policy],
                        resources=resources,
                    )
                ],
                count=2,
            ),
        ]
        provider = set_mocked_huaweicloud_provider(region="eu-west-101")
        provider.session.is_mock = False
        provider.generate_regional_clients.side_effect = None
        provider.generate_regional_clients.return_value = {"eu-west-101": client}

        service = CES(provider)

        assert [alarm.alarm_id for alarm in service.alarms] == ["alarm-1", "alarm-2"]
        assert service.alarms[1].alarm_enabled is False
        assert service.alarms[1].policies == [
            {"metric_name": "cpu_util", "period": 300}
        ]
        assert service.alarms[1].resources == [
            {
                "resource_group_id": "",
                "resource_group_name": "",
                "dimensions": [
                    {"name": "instance_id", "value": "instance-1"},
                    {"name": "disk", "value": "vda"},
                ],
            }
        ]
        assert [
            call.args[0].offset for call in client.list_alarm_rules.call_args_list
        ] == [
            0,
            1,
        ]

    def test_list_alarm_rules_propagates_discovery_errors(self):
        client = mock.MagicMock()
        client.list_alarm_rules.side_effect = RuntimeError("CES unavailable")
        provider = set_mocked_huaweicloud_provider(region="eu-west-101")
        provider.session.is_mock = False
        provider.generate_regional_clients.side_effect = None
        provider.generate_regional_clients.return_value = {"eu-west-101": client}

        with pytest.raises(RuntimeError, match="CES unavailable"):
            CES(provider)
