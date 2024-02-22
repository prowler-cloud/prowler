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
        for log in monitor.diagnostics_settings[AZURE_SUBSCRIPTION][0].logs:
            if log.category == "Administrative":
                assert log.enabled
            if log.category == "Security":
                assert log.enabled
            if log.category == "Alert":
                assert log.enabled
            if log.category == "Policy":
                assert log.enabled
