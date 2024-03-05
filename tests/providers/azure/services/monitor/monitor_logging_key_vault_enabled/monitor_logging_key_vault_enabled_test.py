from unittest import mock

from prowler.providers.azure.services.monitor.monitor_service import (
    DiagnosticSettingForKeyVault,
)
from tests.providers.azure.azure_fixtures import AZURE_SUBSCRIPTION


class Test_monitor_logging_key_vault_enabled:
    def test_monitor_logging_key_vault_enabled_no_subscriptions(self):
        monitor_client = mock.MagicMock
        monitor_client.diagnostics_settings_for_key_vault = {}

        with mock.patch(
            "prowler.providers.azure.services.monitor.monitor_logging_key_vault_enabled.monitor_logging_key_vault_enabled.monitor_client",
            new=monitor_client,
        ):

            from prowler.providers.azure.services.monitor.monitor_logging_key_vault_enabled.monitor_logging_key_vault_enabled import (
                monitor_logging_key_vault_enabled,
            )

            check = monitor_logging_key_vault_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_no_diagnostic_settings(self):
        monitor_client = mock.MagicMock
        monitor_client.diagnostics_settings_for_key_vault = {AZURE_SUBSCRIPTION: []}
        with mock.patch(
            "prowler.providers.azure.services.monitor.monitor_logging_key_vault_enabled.monitor_logging_key_vault_enabled.monitor_client",
            new=monitor_client,
        ):
            from prowler.providers.azure.services.monitor.monitor_logging_key_vault_enabled.monitor_logging_key_vault_enabled import (
                monitor_logging_key_vault_enabled,
            )

            check = monitor_logging_key_vault_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].status == "FAIL"
            assert result[0].resource_id == ""
            assert result[0].resource_name == "Monitor"
            assert (
                result[0].status_extended
                == f"There are no diagnostic settings capturing appropiate categories in subscription {AZURE_SUBSCRIPTION}."
            )

    def test_diagnostic_settings_configured(self):
        monitor_client = mock.MagicMock
        monitor_client.diagnostics_settings_for_key_vault = {
            AZURE_SUBSCRIPTION: [
                DiagnosticSettingForKeyVault(
                    id="id/id1",
                    logs=[
                        mock.MagicMock(category="AuditEvent", enabled=True),
                    ],
                    storage_account_name="storage_account_name",
                    storage_account_id="storage_account_id",
                    type="type",
                    key_vault_name="key_vault_name",
                    resource_group="resource_group",
                ),
                DiagnosticSettingForKeyVault(
                    id="id2/id2",
                    logs=[
                        mock.MagicMock(category="AuditEvent", enabled=False),
                    ],
                    storage_account_name="storage_account_name2",
                    storage_account_id="storage_account_id2",
                    type="type",
                    key_vault_name="key_vault_name2",
                    resource_group="resource_group2",
                ),
            ]
        }
        with mock.patch(
            "prowler.providers.azure.services.monitor.monitor_logging_key_vault_enabled.monitor_logging_key_vault_enabled.monitor_client",
            new=monitor_client,
        ):
            from prowler.providers.azure.services.monitor.monitor_logging_key_vault_enabled.monitor_logging_key_vault_enabled import (
                monitor_logging_key_vault_enabled,
            )

            check = monitor_logging_key_vault_enabled()
            result = check.execute()
            assert len(result) == 2
            assert result[0].status == "PASS"
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == "storage_account_name"
            assert result[0].diagnostic_setting_name == "id1"
            assert (
                result[0].status_extended
                == f"Diagnostic setting id1 for Key Vault in subscription {AZURE_SUBSCRIPTION} is capturing AuditEvent category."
            )
            assert result[1].status == "FAIL"
            assert result[1].subscription == AZURE_SUBSCRIPTION
            assert result[1].resource_name == "storage_account_name2"
            assert result[1].diagnostic_setting_name == "id2"
            assert (
                result[1].status_extended
                == f"Diagnostic setting id2 for Key Vault in subscription {AZURE_SUBSCRIPTION} is not capturing AuditEvent category."
            )
