from unittest import mock

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_monitor_storage_account_with_activity_logs_cmk_encrypted:
    def test_monitor_storage_account_with_activity_logs_cmk_encrypted_no_subscriptions(
        self,
    ):
        monitor_client = mock.MagicMock
        monitor_client.diagnostics_settings = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.monitor.monitor_storage_account_with_activity_logs_cmk_encrypted.monitor_storage_account_with_activity_logs_cmk_encrypted.monitor_client",
            new=monitor_client,
        ):
            from prowler.providers.azure.services.monitor.monitor_storage_account_with_activity_logs_cmk_encrypted.monitor_storage_account_with_activity_logs_cmk_encrypted import (
                monitor_storage_account_with_activity_logs_cmk_encrypted,
            )

            check = monitor_storage_account_with_activity_logs_cmk_encrypted()
            result = check.execute()
            assert len(result) == 0

    def test_no_diagnostic_settings(self):
        monitor_client = mock.MagicMock
        monitor_client.diagnostics_settings = {AZURE_SUBSCRIPTION_ID: []}
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.monitor.monitor_storage_account_with_activity_logs_cmk_encrypted.monitor_storage_account_with_activity_logs_cmk_encrypted.monitor_client",
            new=monitor_client,
        ):
            from prowler.providers.azure.services.monitor.monitor_storage_account_with_activity_logs_cmk_encrypted.monitor_storage_account_with_activity_logs_cmk_encrypted import (
                monitor_storage_account_with_activity_logs_cmk_encrypted,
            )

            check = monitor_storage_account_with_activity_logs_cmk_encrypted()
            result = check.execute()
            assert len(result) == 0

    def test_diagnostic_settings_configured(self):
        monitor_client = mock.MagicMock
        storage_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.monitor.monitor_storage_account_with_activity_logs_cmk_encrypted.monitor_storage_account_with_activity_logs_cmk_encrypted.monitor_client",
            new=monitor_client,
        ):
            with mock.patch(
                "prowler.providers.azure.services.monitor.monitor_storage_account_with_activity_logs_cmk_encrypted.monitor_storage_account_with_activity_logs_cmk_encrypted.storage_client",
                new=storage_client,
            ):
                from prowler.providers.azure.services.monitor.monitor_service import (
                    DiagnosticSetting,
                )
                from prowler.providers.azure.services.monitor.monitor_storage_account_with_activity_logs_cmk_encrypted.monitor_storage_account_with_activity_logs_cmk_encrypted import (
                    monitor_storage_account_with_activity_logs_cmk_encrypted,
                )
                from prowler.providers.azure.services.storage.storage_service import (
                    Account,
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
                                mock.MagicMock(
                                    category="Recommendation", enabled=False
                                ),
                                mock.MagicMock(category="Policy", enabled=True),
                                mock.MagicMock(category="Autoscale", enabled=False),
                            ],
                            storage_account_id="/subscriptions/1234a5-123a-123a-123a-1234567890ab/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/storageaccountname1",
                            storage_account_name="storageaccountname1",
                            name="name",
                        ),
                        DiagnosticSetting(
                            id="id2",
                            logs=[
                                mock.MagicMock(category="Administrative", enabled=True),
                                mock.MagicMock(category="Security", enabled=True),
                                mock.MagicMock(category="ServiceHealth", enabled=False),
                                mock.MagicMock(category="Alert", enabled=True),
                                mock.MagicMock(
                                    category="Recommendation", enabled=False
                                ),
                                mock.MagicMock(category="Policy", enabled=True),
                                mock.MagicMock(category="Autoscale", enabled=False),
                            ],
                            storage_account_id="/subscriptions/1224a5-123a-123a-123a-1234567890ab/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/storageaccountname2",
                            storage_account_name="storageaccountname2",
                            name="name2",
                        ),
                    ]
                }
                storage_client.storage_accounts = {
                    AZURE_SUBSCRIPTION_ID: [
                        Account(
                            id="/subscriptions/1234a5-123a-123a-123a-1234567890ab/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/storageaccountname1",
                            name="storageaccountname1",
                            resouce_group_name="rg",
                            enable_https_traffic_only=True,
                            infrastructure_encryption="Enabled",
                            allow_blob_public_access=True,
                            network_rule_set="AllowAll",
                            encryption_type="Microsoft.CustomerManagedKeyVault",
                            minimum_tls_version="TLS1_2",
                            private_endpoint_connections=[],
                            key_expiration_period_in_days=365,
                            location="euwest",
                            blob_properties=mock.MagicMock(
                                id="id",
                                name="name",
                                type="type",
                                default_service_version="default_service_version",
                                container_delete_retention_policy="container_delete_retention_policy",
                            ),
                        ),
                        Account(
                            id="/subscriptions/1224a5-123a-123a-123a-1234567890ab/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/storageaccountname2",
                            name="storageaccountname2",
                            resouce_group_name="rg",
                            enable_https_traffic_only=False,
                            infrastructure_encryption="Enabled",
                            allow_blob_public_access=False,
                            network_rule_set="AllowAll",
                            encryption_type="Microsoft.Storage",
                            minimum_tls_version="TLS1_2",
                            private_endpoint_connections=[],
                            key_expiration_period_in_days=365,
                            location="euwest",
                            blob_properties=mock.MagicMock(
                                id="id",
                                name="name",
                                type="type",
                                default_service_version="default_service_version",
                                container_delete_retention_policy="container_delete_retention_policy",
                            ),
                        ),
                    ]
                }

                check = monitor_storage_account_with_activity_logs_cmk_encrypted()
                result = check.execute()
                assert len(result) == 2
                assert result[0].subscription == AZURE_SUBSCRIPTION_ID
                assert result[0].status == "PASS"
                assert result[0].resource_name == "storageaccountname1"
                assert result[0].location == "euwest"
                assert (
                    result[0].resource_id
                    == "/subscriptions/1234a5-123a-123a-123a-1234567890ab/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/storageaccountname1"
                )
                assert (
                    result[0].status_extended
                    == f"Storage account {storage_client.storage_accounts[AZURE_SUBSCRIPTION_ID][0].name} storing activity log in subscription {AZURE_SUBSCRIPTION_ID} is encrypted with Customer Managed Key or not necessary."
                )
                assert result[1].status == "FAIL"
                assert result[1].resource_name == "storageaccountname2"
                assert result[1].location == "euwest"
                assert (
                    result[1].resource_id
                    == "/subscriptions/1224a5-123a-123a-123a-1234567890ab/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/storageaccountname2"
                )
                assert (
                    result[1].status_extended
                    == f"Storage account {storage_client.storage_accounts[AZURE_SUBSCRIPTION_ID][1].name} storing activity log in subscription {AZURE_SUBSCRIPTION_ID} is not encrypted with Customer Managed Key."
                )
