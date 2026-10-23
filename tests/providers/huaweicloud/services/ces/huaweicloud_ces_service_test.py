from types import SimpleNamespace
from unittest import mock

from prowler.providers.huaweicloud.services.ces.ces_service import CES, CESAlarm
from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)

REGION = "la-south-2"


def _provider_with_client(regional_client):
    """Return a mocked provider whose regional client is the given mock."""
    provider = set_mocked_huaweicloud_provider(region=REGION)
    provider.generate_regional_clients = mock.MagicMock(
        return_value={REGION: regional_client}
    )
    return provider


class TestCESService:
    def test_list_alarms_parses_alarms(self):
        alarm_1 = SimpleNamespace(
            alarm_id="alarm-001",
            alarm_name="cpu-alarm",
            alarm_enabled=True,
        )
        alarm_2 = SimpleNamespace(
            alarm_id="alarm-002",
            alarm_name="disk-alarm",
            alarm_enabled=False,
        )
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_alarms.return_value = SimpleNamespace(
            metric_alarms=[alarm_1, alarm_2]
        )

        ces = CES(_provider_with_client(regional_client))

        assert len(ces.alarms) == 2
        assert isinstance(ces.alarms[0], CESAlarm)
        assert ces.alarms[0].alarm_id == "alarm-001"
        assert ces.alarms[0].alarm_name == "cpu-alarm"
        assert ces.alarms[0].alarm_enabled is True
        assert ces.alarms[0].region == REGION
        assert ces.alarms[1].alarm_id == "alarm-002"
        assert ces.alarms[1].alarm_name == "disk-alarm"
        assert ces.alarms[1].alarm_enabled is False
        assert ces.alarms[1].region == REGION

    def test_list_alarms_empty(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_alarms.return_value = SimpleNamespace(metric_alarms=[])

        ces = CES(_provider_with_client(regional_client))

        assert ces.alarms == []

    def test_list_alarms_handles_sdk_error(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_alarms.side_effect = Exception("boom")

        ces = CES(_provider_with_client(regional_client))

        assert ces.alarms == []
