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
                logs=[
                    mock.MagicMock(category="Administrative", enabled=True),
                    mock.MagicMock(category="Security", enabled=True),
                    mock.MagicMock(category="ServiceHealth", enabled=False),
                    mock.MagicMock(category="Alert", enabled=True),
                    mock.MagicMock(category="Recommendation", enabled=False),
                    mock.MagicMock(category="Policy", enabled=True),
                    mock.MagicMock(category="Autoscale", enabled=False),
                    mock.MagicMock(category="ResourceHealth", enabled=False),
                ],
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
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].logs[0].enabled is True
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].logs[0].category
            == "Administrative"
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].logs[1].enabled is True
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].logs[1].category
            == "Security"
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].logs[2].category
            == "ServiceHealth"
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].logs[3].enabled is True
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].logs[3].category
            == "Alert"
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].logs[4].category
            == "Recommendation"
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].logs[5].enabled is True
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].logs[5].category
            == "Policy"
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].logs[6].category
            == "Autoscale"
        )
        assert (
            monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].logs[7].category
            == "ResourceHealth"
        )
