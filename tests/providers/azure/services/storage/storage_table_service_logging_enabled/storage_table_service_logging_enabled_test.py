from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.monitor.monitor_service import (
    DiagnosticSetting,
    LogSettings,
)
from prowler.providers.azure.services.storage.storage_service import (
    Account,
    NetworkRuleSet,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)

CHECK_MODULE_PATH = (
    "prowler.providers.azure.services.storage."
    "storage_table_service_logging_enabled."
    "storage_table_service_logging_enabled"
)


def _make_account(
    account_id=None,
    name="teststorageaccount",
    kind="StorageV2",
    table_service_diagnostic_settings=None,
):
    """Create a minimal Account for testing."""
    return Account(
        id=account_id or str(uuid4()),
        name=name,
        kind=kind,
        resouce_group_name="rg",
        enable_https_traffic_only=True,
        infrastructure_encryption=False,
        allow_blob_public_access=False,
        network_rule_set=NetworkRuleSet(bypass="AzureServices", default_action="Allow"),
        encryption_type="Microsoft.Storage",
        minimum_tls_version="TLS1_2",
        key_expiration_period_in_days=None,
        location="westeurope",
        private_endpoint_connections=[],
        table_service_diagnostic_settings=table_service_diagnostic_settings,
    )


def _diag_with_categories(categories, enabled=True):
    """Build a DiagnosticSetting with the given categories enabled."""
    return DiagnosticSetting(
        id="/diag-id",
        name="diag-table",
        storage_account_id=None,
        storage_account_name=None,
        logs=[
            LogSettings(category=cat, category_group=None, enabled=enabled)
            for cat in categories
        ],
    )


def _diag_with_all_logs():
    """Build a DiagnosticSetting with the allLogs category group enabled."""
    return DiagnosticSetting(
        id="/diag-id",
        name="diag-table-all",
        storage_account_id=None,
        storage_account_name=None,
        logs=[
            LogSettings(category=None, category_group="allLogs", enabled=True),
        ],
    )


class Test_storage_table_service_logging_enabled:
    def test_no_storage_accounts(self):
        """No storage accounts should produce zero findings."""
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_table_service_logging_enabled.storage_table_service_logging_enabled import (
                storage_table_service_logging_enabled,
            )

            check = storage_table_service_logging_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_skip_blob_storage_kind(self):
        """BlobStorage accounts should be skipped (no Table service)."""
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(kind="BlobStorage"),
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_table_service_logging_enabled.storage_table_service_logging_enabled import (
                storage_table_service_logging_enabled,
            )

            check = storage_table_service_logging_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_skip_block_blob_storage_kind(self):
        """BlockBlobStorage accounts should be skipped (no Table service)."""
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(kind="BlockBlobStorage"),
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_table_service_logging_enabled.storage_table_service_logging_enabled import (
                storage_table_service_logging_enabled,
            )

            check = storage_table_service_logging_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_skip_file_storage_kind(self):
        """FileStorage accounts should be skipped (no Table service)."""
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(kind="FileStorage"),
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_table_service_logging_enabled.storage_table_service_logging_enabled import (
                storage_table_service_logging_enabled,
            )

            check = storage_table_service_logging_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_diagnostic_settings_none_emits_manual(self):
        """When diagnostic settings could not be read, emit MANUAL."""
        account_name = "manualaccount"
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    name=account_name,
                    table_service_diagnostic_settings=None,
                ),
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_table_service_logging_enabled.storage_table_service_logging_enabled import (
                storage_table_service_logging_enabled,
            )

            check = storage_table_service_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "Could not retrieve" in result[0].status_extended
            assert account_name in result[0].status_extended

    def test_no_diagnostic_settings_emits_fail(self):
        """When there are no diagnostic settings (empty list), emit FAIL."""
        account_id = str(uuid4())
        account_name = "failaccount"
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    account_id=account_id,
                    name=account_name,
                    table_service_diagnostic_settings=[],
                ),
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_table_service_logging_enabled.storage_table_service_logging_enabled import (
                storage_table_service_logging_enabled,
            )

            check = storage_table_service_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "StorageDelete" in result[0].status_extended
            assert "StorageRead" in result[0].status_extended
            assert "StorageWrite" in result[0].status_extended
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == account_name
            assert result[0].resource_id == account_id

    def test_all_categories_enabled_pass(self):
        """PASS when all three required categories are enabled."""
        account_id = str(uuid4())
        account_name = "passaccount"
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    account_id=account_id,
                    name=account_name,
                    table_service_diagnostic_settings=[
                        _diag_with_categories(
                            ["StorageRead", "StorageWrite", "StorageDelete"]
                        ),
                    ],
                ),
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_table_service_logging_enabled.storage_table_service_logging_enabled import (
                storage_table_service_logging_enabled,
            )

            check = storage_table_service_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == account_name
            assert result[0].resource_id == account_id
            assert result[0].location == "westeurope"

    def test_partial_categories_fail(self):
        """FAIL when only some categories are enabled."""
        account_name = "partialaccount"
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    name=account_name,
                    table_service_diagnostic_settings=[
                        _diag_with_categories(["StorageRead", "StorageWrite"]),
                    ],
                ),
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_table_service_logging_enabled.storage_table_service_logging_enabled import (
                storage_table_service_logging_enabled,
            )

            check = storage_table_service_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "StorageDelete" in result[0].status_extended
            assert "StorageRead" not in result[0].status_extended.split("for: ")[1]

    def test_all_logs_category_group_pass(self):
        """PASS when the allLogs category group is enabled."""
        account_name = "alllogsaccount"
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    name=account_name,
                    table_service_diagnostic_settings=[
                        _diag_with_all_logs(),
                    ],
                ),
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_table_service_logging_enabled.storage_table_service_logging_enabled import (
                storage_table_service_logging_enabled,
            )

            check = storage_table_service_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_categories_across_multiple_settings_pass(self):
        """PASS when required categories are split across multiple diagnostic settings."""
        account_name = "splitaccount"
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    name=account_name,
                    table_service_diagnostic_settings=[
                        _diag_with_categories(["StorageRead"]),
                        _diag_with_categories(["StorageWrite", "StorageDelete"]),
                    ],
                ),
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_table_service_logging_enabled.storage_table_service_logging_enabled import (
                storage_table_service_logging_enabled,
            )

            check = storage_table_service_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_categories_present_but_disabled_fail(self):
        """FAIL when categories exist but are disabled."""
        account_name = "disabledaccount"
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    name=account_name,
                    table_service_diagnostic_settings=[
                        _diag_with_categories(
                            ["StorageRead", "StorageWrite", "StorageDelete"],
                            enabled=False,
                        ),
                    ],
                ),
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_table_service_logging_enabled.storage_table_service_logging_enabled import (
                storage_table_service_logging_enabled,
            )

            check = storage_table_service_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_all_logs_disabled_fail(self):
        """FAIL when allLogs category group exists but is disabled."""
        account_name = "allogsdisabled"
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    name=account_name,
                    table_service_diagnostic_settings=[
                        DiagnosticSetting(
                            id="/diag-id",
                            name="diag-table-all",
                            storage_account_id=None,
                            storage_account_name=None,
                            logs=[
                                LogSettings(
                                    category=None,
                                    category_group="allLogs",
                                    enabled=False,
                                ),
                            ],
                        ),
                    ],
                ),
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_table_service_logging_enabled.storage_table_service_logging_enabled import (
                storage_table_service_logging_enabled,
            )

            check = storage_table_service_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_multiple_accounts_mixed_results(self):
        """Multiple accounts: one PASS, one FAIL."""
        pass_id = str(uuid4())
        fail_id = str(uuid4())
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    account_id=pass_id,
                    name="passaccount",
                    table_service_diagnostic_settings=[
                        _diag_with_categories(
                            ["StorageRead", "StorageWrite", "StorageDelete"]
                        ),
                    ],
                ),
                _make_account(
                    account_id=fail_id,
                    name="failaccount",
                    table_service_diagnostic_settings=[],
                ),
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_table_service_logging_enabled.storage_table_service_logging_enabled import (
                storage_table_service_logging_enabled,
            )

            check = storage_table_service_logging_enabled()
            result = check.execute()
            assert len(result) == 2
            results_by_id = {r.resource_id: r for r in result}
            assert results_by_id[pass_id].status == "PASS"
            assert results_by_id[fail_id].status == "FAIL"

    def test_single_category_fail_lists_missing(self):
        """FAIL when only one category is enabled; status_extended lists the two missing."""
        account_name = "onlyreadaccount"
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    name=account_name,
                    table_service_diagnostic_settings=[
                        _diag_with_categories(["StorageRead"]),
                    ],
                ),
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_table_service_logging_enabled.storage_table_service_logging_enabled import (
                storage_table_service_logging_enabled,
            )

            check = storage_table_service_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            missing_part = result[0].status_extended.split("for: ")[1]
            assert "StorageDelete" in missing_part
            assert "StorageWrite" in missing_part
            assert "StorageRead" not in missing_part

    def test_fail_with_status_extended(self):
        """Verify full status_extended message on FAIL."""
        account_name = "fullfailaccount"
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    name=account_name,
                    table_service_diagnostic_settings=[],
                ),
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_table_service_logging_enabled.storage_table_service_logging_enabled import (
                storage_table_service_logging_enabled,
            )

            check = storage_table_service_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Storage account {account_name} in subscription "
                f"{AZURE_SUBSCRIPTION_DISPLAY} does not have "
                f"Table service logging enabled for: "
                f"StorageDelete, StorageRead, StorageWrite."
            )

    def test_storage_v2_pass_with_status_extended(self):
        """Verify full status_extended message on PASS."""
        account_name = "fullpassaccount"
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    name=account_name,
                    kind="StorageV2",
                    table_service_diagnostic_settings=[
                        _diag_with_categories(
                            ["StorageRead", "StorageWrite", "StorageDelete"]
                        ),
                    ],
                ),
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_table_service_logging_enabled.storage_table_service_logging_enabled import (
                storage_table_service_logging_enabled,
            )

            check = storage_table_service_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Storage account {account_name} in subscription "
                f"{AZURE_SUBSCRIPTION_DISPLAY} has Table service "
                f"logging enabled for StorageRead, StorageWrite and "
                f"StorageDelete."
            )
