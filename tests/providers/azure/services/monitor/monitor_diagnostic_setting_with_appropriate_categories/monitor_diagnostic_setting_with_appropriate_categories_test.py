from unittest import mock

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_monitor_diagnostic_setting_with_appropriate_categories:
    def test_monitor_diagnostic_setting_with_appropriate_categories_no_subscriptions(
        self,
    ):
        monitor_client = mock.MagicMock
        monitor_client.diagnostics_settings = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.monitor.monitor_diagnostic_setting_with_appropriate_categories.monitor_diagnostic_setting_with_appropriate_categories.monitor_client",
            new=monitor_client,
        ):

            from prowler.providers.azure.services.monitor.monitor_diagnostic_setting_with_appropriate_categories.monitor_diagnostic_setting_with_appropriate_categories import (
                monitor_diagnostic_setting_with_appropriate_categories,
            )

            check = monitor_diagnostic_setting_with_appropriate_categories()
            result = check.execute()
            assert len(result) == 0

    def test_no_diagnostic_settings(self):
        monitor_client = mock.MagicMock
        monitor_client.diagnostics_settings = {AZURE_SUBSCRIPTION_ID: []}
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.monitor.monitor_diagnostic_setting_with_appropriate_categories.monitor_diagnostic_setting_with_appropriate_categories.monitor_client",
            new=monitor_client,
        ):
            from prowler.providers.azure.services.monitor.monitor_diagnostic_setting_with_appropriate_categories.monitor_diagnostic_setting_with_appropriate_categories import (
                monitor_diagnostic_setting_with_appropriate_categories,
            )

            check = monitor_diagnostic_setting_with_appropriate_categories()
            result = check.execute()
            assert len(result) == 1
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "Monitor"
            assert result[0].resource_name == "Monitor"
            assert (
                result[0].status_extended
                == f"There are no diagnostic settings capturing appropiate categories in subscription {AZURE_SUBSCRIPTION_ID}."
            )

    def test_diagnostic_settings_configured(self):
        monitor_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.monitor.monitor_diagnostic_setting_with_appropriate_categories.monitor_diagnostic_setting_with_appropriate_categories.monitor_client",
            new=monitor_client,
        ):
            from prowler.providers.azure.services.monitor.monitor_diagnostic_setting_with_appropriate_categories.monitor_diagnostic_setting_with_appropriate_categories import (
                monitor_diagnostic_setting_with_appropriate_categories,
            )
            from prowler.providers.azure.services.monitor.monitor_service import (
                DiagnosticSetting,
            )

            monitor_client.diagnostics_settings = {
                AZURE_SUBSCRIPTION_ID: [
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
                        storage_account_id="/subscriptions/1234a5-123a-123a-123a-1234567890ab/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/storageaccountname",
                        storage_account_name="storageaccountname",
                        name="name",
                    ),
                    DiagnosticSetting(
                        id="id2",
                        logs=[
                            mock.MagicMock(category="Administrative", enabled=False),
                            mock.MagicMock(category="Security", enabled=True),
                            mock.MagicMock(category="ServiceHealth", enabled=False),
                            mock.MagicMock(category="Alert", enabled=True),
                            mock.MagicMock(category="Recommendation", enabled=False),
                            mock.MagicMock(category="Policy", enabled=True),
                            mock.MagicMock(category="Autoscale", enabled=False),
                            mock.MagicMock(category="ResourceHealth", enabled=False),
                        ],
                        storage_account_id="/subscriptions/1224a5-123a-123a-123a-1234567890ab/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/storageaccountname2",
                        storage_account_name="storageaccountname2",
                        name="name2",
                    ),
                ]
            }
            check = monitor_diagnostic_setting_with_appropriate_categories()
            result = check.execute()
            assert len(result) == 1
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].status == "PASS"
            assert result[0].resource_id == "Monitor"
            assert result[0].resource_name == "Monitor"
            assert (
                result[0].status_extended
                == f"There is at least one diagnostic setting capturing appropiate categories in subscription {AZURE_SUBSCRIPTION_ID}."
            )
