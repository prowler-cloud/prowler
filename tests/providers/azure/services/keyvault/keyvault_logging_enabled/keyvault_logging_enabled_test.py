from unittest import mock

from azure.mgmt.keyvault.v2023_07_01.models import VaultProperties

from prowler.providers.azure.services.keyvault.keyvault_service import KeyVaultInfo
from prowler.providers.azure.services.monitor.monitor_service import DiagnosticSetting
from tests.providers.azure.azure_fixtures import AZURE_SUBSCRIPTION


class Test_keyvault_logging_enabled:
    def test_keyvault_logging_enabled(self):
        keyvault_client = mock.MagicMock
        keyvault_client.key_vaults = {}

        with mock.patch(
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
        keyvault_client.key_vaults = {AZURE_SUBSCRIPTION: []}
        with mock.patch(
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
        keyvault_client.key_vaults = {
            AZURE_SUBSCRIPTION: [
                KeyVaultInfo(
                    id="id",
                    name="name_keyvault",
                    location="location",
                    resource_group="resource_group",
                    properties=VaultProperties(
                        tenant_id="tenantid", sku="sku", enable_rbac_authorization=False
                    ),
                    keys=[],
                    secrets=[],
                    monitor_diagnostic_settings=[
                        DiagnosticSetting(
                            id="id/id",
                            logs=[
                                mock.MagicMock(category="AuditEvent", enabled=True),
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
                    location="location2",
                    resource_group="resource_group2",
                    properties=VaultProperties(
                        tenant_id="tenantid", sku="sku", enable_rbac_authorization=False
                    ),
                    keys=[],
                    secrets=[],
                    monitor_diagnostic_settings=[
                        DiagnosticSetting(
                            id="id2/id2",
                            logs=[
                                mock.MagicMock(category="AuditEvent", enabled=False),
                            ],
                            storage_account_name="storage_account_name2",
                            storage_account_id="storage_account_id2",
                            name="name_diagnostic_setting2",
                        ),
                    ],
                ),
            ]
        }
        with mock.patch(
            "prowler.providers.azure.services.keyvault.keyvault_logging_enabled.keyvault_logging_enabled.keyvault_client",
            new=keyvault_client,
        ):
            from prowler.providers.azure.services.keyvault.keyvault_logging_enabled.keyvault_logging_enabled import (
                keyvault_logging_enabled,
            )

            check = keyvault_logging_enabled()
            result = check.execute()
            assert len(result) == 2
            assert result[0].status == "PASS"
            assert result[0].subscription == AZURE_SUBSCRIPTION
            assert result[0].resource_name == "name_diagnostic_setting"
            assert result[0].diagnostic_setting_name == "name_diagnostic_setting"
            assert result[0].resource_id == "id/id"
            assert (
                result[0].status_extended
                == f"Diagnostic setting name_diagnostic_setting for Key Vault name_keyvault in subscription {AZURE_SUBSCRIPTION} is capturing AuditEvent category."
            )
            assert result[1].status == "FAIL"
            assert result[1].subscription == AZURE_SUBSCRIPTION
            assert result[1].resource_name == "name_diagnostic_setting2"
            assert result[1].diagnostic_setting_name == "name_diagnostic_setting2"
            assert result[1].resource_id == "id2/id2"
            assert (
                result[1].status_extended
                == f"Diagnostic setting name_diagnostic_setting2 for Key Vault name_keyvault2 in subscription {AZURE_SUBSCRIPTION} is not capturing AuditEvent category."
            )
