from unittest import mock

from azure.mgmt.keyvault.v2023_07_01.models import VaultProperties

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_keyvault_logging_enabled:
    def test_no_key_vaults(self):
        keyvault_client = mock.MagicMock
        keyvault_client.key_vaults = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.monitor.monitor_service.Monitor",
                new=mock.MagicMock(),
            ),
            mock.patch(
                "prowler.providers.azure.services.keyvault.keyvault_logging_enabled.keyvault_logging_enabled.keyvault_client",
                new=keyvault_client,
            ),
        ):
            from prowler.providers.azure.services.keyvault.keyvault_logging_enabled.keyvault_logging_enabled import (
                keyvault_logging_enabled,
            )

            check = keyvault_logging_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_no_diagnostic_settings(self):
        keyvault_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.monitor.monitor_service.Monitor",
                new=mock.MagicMock(),
            ),
            mock.patch(
                "prowler.providers.azure.services.keyvault.keyvault_logging_enabled.keyvault_logging_enabled.keyvault_client",
                new=keyvault_client,
            ),
        ):
            from prowler.providers.azure.services.keyvault.keyvault_logging_enabled.keyvault_logging_enabled import (
                keyvault_logging_enabled,
            )
            from prowler.providers.azure.services.keyvault.keyvault_service import (
                KeyVaultInfo,
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
                        monitor_diagnostic_settings=[],
                    ),
                ]
            }
            check = keyvault_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Key Vault name_keyvault in subscription {AZURE_SUBSCRIPTION_ID} does not have a diagnostic setting with audit logging."
            )
            assert result[0].resource_name == "name_keyvault"
            assert result[0].resource_id == "id"

    def test_diagnostic_setting_without_audit_logging(self):
        keyvault_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.monitor.monitor_service.Monitor",
                new=mock.MagicMock(),
            ),
            mock.patch(
                "prowler.providers.azure.services.keyvault.keyvault_logging_enabled.keyvault_logging_enabled.keyvault_client",
                new=keyvault_client,
            ),
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
                                id="id/ds1",
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
                                storage_account_name="sa1",
                                storage_account_id="sa_id1",
                                name="ds_incomplete",
                            ),
                        ],
                    ),
                ]
            }
            check = keyvault_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Key Vault name_keyvault in subscription {AZURE_SUBSCRIPTION_ID} does not have a diagnostic setting with audit logging."
            )
            assert result[0].resource_name == "name_keyvault"
            assert result[0].resource_id == "id"

    def test_diagnostic_setting_with_audit_logging(self):
        keyvault_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.monitor.monitor_service.Monitor",
                new=mock.MagicMock(),
            ),
            mock.patch(
                "prowler.providers.azure.services.keyvault.keyvault_logging_enabled.keyvault_logging_enabled.keyvault_client",
                new=keyvault_client,
            ),
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
                                id="id/ds1",
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
                                storage_account_name="sa1",
                                storage_account_id="sa_id1",
                                name="ds_compliant",
                            ),
                        ],
                    ),
                ]
            }
            check = keyvault_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Key Vault name_keyvault in subscription {AZURE_SUBSCRIPTION_ID} has a diagnostic setting with audit logging."
            )
            assert result[0].resource_name == "name_keyvault"
            assert result[0].resource_id == "id"

    def test_multiple_diagnostic_settings_one_compliant(self):
        keyvault_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.monitor.monitor_service.Monitor",
                new=mock.MagicMock(),
            ),
            mock.patch(
                "prowler.providers.azure.services.keyvault.keyvault_logging_enabled.keyvault_logging_enabled.keyvault_client",
                new=keyvault_client,
            ),
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
                                id="id/ds1",
                                logs=[
                                    mock.MagicMock(
                                        category_group="audit",
                                        category="None",
                                        enabled=False,
                                    ),
                                    mock.MagicMock(
                                        category_group="allLogs",
                                        category="None",
                                        enabled=False,
                                    ),
                                ],
                                storage_account_name="sa1",
                                storage_account_id="sa_id1",
                                name="ds_noncompliant",
                            ),
                            DiagnosticSetting(
                                id="id/ds2",
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
                                storage_account_name="sa2",
                                storage_account_id="sa_id2",
                                name="ds_compliant",
                            ),
                        ],
                    ),
                ]
            }
            check = keyvault_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_name == "name_keyvault"
            assert result[0].resource_id == "id"

    def test_multiple_vaults_mixed(self):
        keyvault_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.monitor.monitor_service.Monitor",
                new=mock.MagicMock(),
            ),
            mock.patch(
                "prowler.providers.azure.services.keyvault.keyvault_logging_enabled.keyvault_logging_enabled.keyvault_client",
                new=keyvault_client,
            ),
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
                        id="id1",
                        name="vault_fail",
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
                                id="id1/ds1",
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
                                storage_account_name="sa1",
                                storage_account_id="sa_id1",
                                name="ds_incomplete",
                            ),
                        ],
                    ),
                    KeyVaultInfo(
                        id="id2",
                        name="vault_pass",
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
                                id="id2/ds2",
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
                                storage_account_name="sa2",
                                storage_account_id="sa_id2",
                                name="ds_compliant",
                            ),
                        ],
                    ),
                ]
            }
            check = keyvault_logging_enabled()
            result = check.execute()
            assert len(result) == 2
            assert result[0].status == "FAIL"
            assert result[0].resource_name == "vault_fail"
            assert result[0].resource_id == "id1"
            assert result[1].status == "PASS"
            assert result[1].resource_name == "vault_pass"
            assert result[1].resource_id == "id2"
