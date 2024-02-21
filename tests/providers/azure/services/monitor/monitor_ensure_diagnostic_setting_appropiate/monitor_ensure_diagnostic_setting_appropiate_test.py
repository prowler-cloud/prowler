from unittest import mock

from prowler.providers.azure.services.monitor.monitor_service import DiagnosticSetting
from tests.providers.azure.azure_fixtures import AZURE_SUBSCRIPTION


class Test_monitor_ensure_diagnostic_setting_appropiate:
    def test_monitor_ensure_diagnostic_setting_appropiate_no_subscriptions(self):
        monitor_client = mock.MagicMock
        monitor_client.diagnostics_settings = {}

        with mock.patch(
            "prowler.providers.azure.services.monitor.monitor_ensure_diagnostic_setting_appropiate.monitor_ensure_diagnostic_setting_appropiate.monitor_client",
            new=monitor_client,
        ):
            from prowler.providers.azure.services.monitor.monitor_ensure_diagnostic_setting_appropiate.monitor_ensure_diagnostic_setting_appropiate import (
                monitor_ensure_diagnostic_setting_appropiate,
            )

            check = monitor_ensure_diagnostic_setting_appropiate()
            result = check.execute()
            assert len(result) == 0

    def test_no_diagnostic_settings(self):
        monitor_client = mock.MagicMock
        monitor_client.diagnostics_settings = {AZURE_SUBSCRIPTION: []}
        with mock.patch(
            "prowler.providers.azure.services.monitor.monitor_ensure_diagnostic_setting_appropiate.monitor_ensure_diagnostic_setting_appropiate.monitor_client",
            new=monitor_client,
        ):
            from prowler.providers.azure.services.monitor.monitor_ensure_diagnostic_setting_appropiate.monitor_ensure_diagnostic_setting_appropiate import (
                monitor_ensure_diagnostic_setting_appropiate,
            )

            check = monitor_ensure_diagnostic_setting_appropiate()
            result = check.execute()
            assert len(result) == 1
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "Monitor"
            assert result[0].resource_name == "Monitor"
            assert (
                result[0].status_extended
                == f"There are no diagnostic settings capturing appropiate categories in subscription {AZURE_SUBSCRIPTION}."
            )

    def test_diagnostic_settings_configured(self):
        monitor_client = mock.MagicMock
        monitor_client.diagnostics_settings = {
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

        with mock.patch(
            "prowler.providers.azure.services.monitor.monitor_ensure_diagnostic_setting_appropiate.monitor_ensure_diagnostic_setting_appropiate.monitor_client",
            new=monitor_client,
        ):
            from prowler.providers.azure.services.monitor.monitor_ensure_diagnostic_setting_appropiate.monitor_ensure_diagnostic_setting_appropiate import (
                monitor_ensure_diagnostic_setting_appropiate,
            )

            check = monitor_ensure_diagnostic_setting_appropiate()
            result = check.execute()
            assert len(result) == 1
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].status == "PASS"
            assert result[0].resource_id == "Monitor"
            assert result[0].resource_name == "Monitor"
            assert (
                result[0].status_extended
                == f"There is at least one diagnostic setting capturing appropiate categories in subscription {AZURE_SUBSCRIPTION}."
            )
