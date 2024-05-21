from unittest import mock

from azure.mgmt.keyvault.v2023_07_01.models import VaultProperties

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_keyvault_logging_enabled:
    def test_keyvault_logging_enabled(self):
        keyvault_client = mock.MagicMock
        keyvault_client.key_vaults = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.monitor.monitor_service.Monitor",
            new=mock.MagicMock(),
        ), mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_logging_enabled.keyvault_logging_enabled.keyvault_client",
            new=keyvault_client,
        ):

            from prowler.providers.azure.services.keyvault.keyvault_logging_enabled.keyvault_logging_enabled import (
                keyvault_logging_enabled,
            )

            check = keyvault_logging_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_no_diagnostic_settings(self):
        keyvault_client = mock.MagicMock
        keyvault_client.key_vaults = {AZURE_SUBSCRIPTION_ID: []}
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.monitor.monitor_service.Monitor",
            new=mock.MagicMock(),
        ), mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_logging_enabled.keyvault_logging_enabled.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_logging_enabled.keyvault_logging_enabled import (
                keyvault_logging_enabled,
            )

            check = keyvault_logging_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_diagnostic_settings_configured(self):
        keyvault_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.monitor.monitor_service.Monitor",
            new=mock.MagicMock(),
        ), mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_logging_enabled.keyvault_logging_enabled.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_logging_enabled.keyvault_logging_enabled import (
                keyvault_logging_enabled,
            )
            from prowler.providers.azure.services.keyvault.keyvault_service import (
                KeyVaultInfo,
            )
            from prowler.providers.azure.services.monitor.monitor_service import (
                DiagnosticSetting,
            )

            keyvault_client.key_vaults = {
                AZURE_SUBSCRIPTION_ID: [
                    KeyVaultInfo(
                        id="id",
                        name="name_keyvault",
                        location="westeurope",
                        resource_group="resource_group",
                        properties=VaultProperties(
                            tenant_id="tenantid",
                            sku="sku",
                            enable_rbac_authorization=False,
                        ),
                        keys=[],
                        secrets=[],
                        monitor_diagnostic_settings=[
                            DiagnosticSetting(
                                id="id/id",
                                logs=[
                                    mock.MagicMock(
                                        category_group="audit",
                                        category="None",
                                        enabled=True,
                                    ),
                                    mock.MagicMock(
                                        category_group="allLogs",
                                        category="None",
                                        enabled=False,
                                    ),
                                ],
                                storage_account_name="storage_account_name",
                                storage_account_id="storage_account_id",
                                name="name_diagnostic_setting",
                            ),
                        ],
                    ),
                    KeyVaultInfo(
                        id="id2",
                        name="name_keyvault2",
                        location="eastus",
                        resource_group="resource_group2",
                        properties=VaultProperties(
                            tenant_id="tenantid",
                            sku="sku",
                            enable_rbac_authorization=False,
                        ),
                        keys=[],
                        secrets=[],
                        monitor_diagnostic_settings=[
                            DiagnosticSetting(
                                id="id2/id2",
                                logs=[
                                    mock.MagicMock(
                                        category_group="audit",
                                        category="None",
                                        enabled=True,
                                    ),
                                    mock.MagicMock(
                                        category_group="allLogs",
                                        category="None",
                                        enabled=True,
                                    ),
                                ],
                                storage_account_name="storage_account_name2",
                                storage_account_id="storage_account_id2",
                                name="name_diagnostic_setting2",
                            ),
                        ],
                    ),
                ]
            }
            check = keyvault_logging_enabled()
            result = check.execute()
            assert len(result) == 2
            assert result[0].status == "FAIL"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "name_diagnostic_setting"
            assert result[0].resource_id == "id/id"
            assert result[0].location == "westeurope"
            assert (
                result[0].status_extended
                == f"Diagnostic setting name_diagnostic_setting for Key Vault name_keyvault in subscription {AZURE_SUBSCRIPTION_ID} does not have audit logging."
            )
            assert result[1].status == "PASS"
            assert result[1].subscription == AZURE_SUBSCRIPTION_ID
            assert result[1].resource_name == "name_diagnostic_setting2"
            assert result[1].resource_id == "id2/id2"
            assert result[1].location == "eastus"
            assert (
                result[1].status_extended
                == f"Diagnostic setting name_diagnostic_setting2 for Key Vault name_keyvault2 in subscription {AZURE_SUBSCRIPTION_ID} has audit logging."
            )
