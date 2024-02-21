from unittest import mock
from unittest.mock import patch

from prowler.providers.azure.services.monitor.monitor_service import (
    DiagnosticSetting,
    Monitor,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_audit_info,
)


def mock_monitor_get_diagnostics_settings(_):
    return {
        AZURE_SUBSCRIPTION: [
            DiagnosticSetting(
                id="id",
                name="name",
                type="type",
                event_hub_authorization_rule_id="event_hub_authorization_rule_id",
                event_hub_name="event_hub_name",
                metrics="metrics",
                logs=[
                    mock.MagicMock(enabled=True),
                    mock.MagicMock(enabled=True),
                    mock.MagicMock(enabled=True),
                    mock.MagicMock(enabled=True),
                    mock.MagicMock(enabled=False),
                    mock.MagicMock(enabled=True),
                    mock.MagicMock(enabled=False),
                    mock.MagicMock(enabled=False),
                ],
                workspace_id="workspace_id",
                storage_account_id="storage_account_id",
                service_bus_rule_id="service_bus_rule_id",
                marketplace_partner_id="marketplace_partner_id",
                log_analytics_destination_type="log_analytics_destination_type",
            )
        ]
    }


@patch(
    "prowler.providers.azure.services.monitor.monitor_service.Monitor.__get_diagnostics_settings__",
    new=mock_monitor_get_diagnostics_settings,
)
class Test_Monitor_Service:
    def test__get_client__(self):
        monitor = Monitor(set_mocked_azure_audit_info())
        assert (
            monitor.clients[AZURE_SUBSCRIPTION].__class__.__name__
            == "MonitorManagementClient"
        )

    def test__get_subscriptions__(self):
        monitor = Monitor(set_mocked_azure_audit_info())
        assert monitor.subscriptions.__class__.__name__ == "dict"

    def test__get_diagnostics_settings(self):
        monitor = Monitor(set_mocked_azure_audit_info())
        assert len(monitor.diagnostics_settings) == 1
        assert monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].id == "id"
        assert monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].name == "name"
        assert monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].type == "type"
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION][
                0
            ].event_hub_authorization_rule_id
            == "event_hub_authorization_rule_id"
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].event_hub_name
            == "event_hub_name"
        )
        assert monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].metrics == "metrics"

        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].logs[0].enabled is True
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].logs[1].enabled is True
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].logs[2].enabled is True
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].logs[3].enabled is True
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].logs[4].enabled is False
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].logs[5].enabled is True
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].logs[6].enabled is False
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].logs[7].enabled is False
        )
