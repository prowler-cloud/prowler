from unittest import mock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)

CHECK_MODULE_PATH = "prowler.providers.azure.services.storage.storage_blob_service_logging_enabled.storage_blob_service_logging_enabled"


def _make_account(
    account_id,
    account_name,
    blob_properties=None,
    blob_service_diagnostic_settings=None,
    kind="StorageV2",
):
    """Helper to build an Account with sensible defaults."""
    from prowler.providers.azure.services.storage.storage_service import (
        Account,
        NetworkRuleSet,
    )

    return Account(
        id=account_id,
        name=account_name,
        resouce_group_name="rg",
        enable_https_traffic_only=True,
        infrastructure_encryption=False,
        allow_blob_public_access=False,
        network_rule_set=NetworkRuleSet(bypass="AzureServices", default_action="Allow"),
        encryption_type="None",
        minimum_tls_version="TLS1_2",
        key_expiration_period_in_days=None,
        location="westeurope",
        private_endpoint_connections=[],
        blob_properties=blob_properties,
        kind=kind,
        blob_service_diagnostic_settings=blob_service_diagnostic_settings,
    )


def _make_blob_properties():
    """Helper to build a BlobProperties with sensible defaults."""
    from prowler.providers.azure.services.storage.storage_service import (
        BlobProperties,
        DeleteRetentionPolicy,
    )

    return BlobProperties(
        id="id",
        name="default",
        type="type",
        default_service_version=None,
        container_delete_retention_policy=DeleteRetentionPolicy(enabled=False, days=0),
    )


def _make_diag_setting(setting_id, setting_name, logs):
    """Helper to build a DiagnosticSetting."""
    from prowler.providers.azure.services.monitor.monitor_service import (
        DiagnosticSetting,
    )

    return DiagnosticSetting(
        id=setting_id,
        name=setting_name,
        storage_account_name="sa_logs",
        storage_account_id="sa_logs_id",
        logs=logs,
    )


def _make_log(category=None, category_group=None, enabled=True):
    """Helper to build a LogSettings entry."""
    from prowler.providers.azure.services.monitor.monitor_service import (
        LogSettings,
    )

    return LogSettings(
        category=category,
        category_group=category_group,
        enabled=enabled,
    )


class Test_storage_blob_service_logging_enabled:
    """Tests for the storage_blob_service_logging_enabled check."""

    def test_no_storage_accounts(self):
        """No storage accounts should produce no findings."""
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
            from prowler.providers.azure.services.storage.storage_blob_service_logging_enabled.storage_blob_service_logging_enabled import (
                storage_blob_service_logging_enabled,
            )

            check = storage_blob_service_logging_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_file_storage_account_skipped(self):
        """FileStorage accounts have no Blob service and should be skipped."""
        storage_account_id = str(uuid4())
        storage_account_name = "filestorage1"
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    account_id=storage_account_id,
                    account_name=storage_account_name,
                    kind="FileStorage",
                )
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
            from prowler.providers.azure.services.storage.storage_blob_service_logging_enabled.storage_blob_service_logging_enabled import (
                storage_blob_service_logging_enabled,
            )

            check = storage_blob_service_logging_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_diagnostic_settings_none_returns_manual(self):
        """When diagnostic settings could not be read, emit MANUAL."""
        storage_account_id = str(uuid4())
        storage_account_name = "sa1"
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    account_id=storage_account_id,
                    account_name=storage_account_name,
                    blob_properties=_make_blob_properties(),
                    blob_service_diagnostic_settings=None,
                )
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
            from prowler.providers.azure.services.storage.storage_blob_service_logging_enabled.storage_blob_service_logging_enabled import (
                storage_blob_service_logging_enabled,
            )

            check = storage_blob_service_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "Could not retrieve" in result[0].status_extended
            assert storage_account_name in result[0].status_extended
            assert AZURE_SUBSCRIPTION_ID in result[0].status_extended
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_no_diagnostic_settings_fails(self):
        """Empty diagnostic settings list (no settings configured) should FAIL."""
        storage_account_id = str(uuid4())
        storage_account_name = "sa1"
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    account_id=storage_account_id,
                    account_name=storage_account_name,
                    blob_properties=_make_blob_properties(),
                    blob_service_diagnostic_settings=[],
                )
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
            from prowler.providers.azure.services.storage.storage_blob_service_logging_enabled.storage_blob_service_logging_enabled import (
                storage_blob_service_logging_enabled,
            )

            check = storage_blob_service_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "StorageDelete" in result[0].status_extended
            assert "StorageRead" in result[0].status_extended
            assert "StorageWrite" in result[0].status_extended
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_all_categories_enabled_passes(self):
        """All three required categories enabled in one setting should PASS."""
        storage_account_id = str(uuid4())
        storage_account_name = "sa1"
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    account_id=storage_account_id,
                    account_name=storage_account_name,
                    blob_properties=_make_blob_properties(),
                    blob_service_diagnostic_settings=[
                        _make_diag_setting(
                            "diag-id",
                            "diag-blob",
                            logs=[
                                _make_log(category="StorageRead"),
                                _make_log(category="StorageWrite"),
                                _make_log(category="StorageDelete"),
                            ],
                        ),
                    ],
                )
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
            from prowler.providers.azure.services.storage.storage_blob_service_logging_enabled.storage_blob_service_logging_enabled import (
                storage_blob_service_logging_enabled,
            )

            check = storage_blob_service_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Storage account {storage_account_name} in "
                f"subscription {AZURE_SUBSCRIPTION_DISPLAY} has Blob service "
                f"diagnostic logging enabled for read, write and delete requests."
            )
            assert result[0].resource_name == storage_account_name
            assert result[0].resource_id == storage_account_id
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "westeurope"

    def test_missing_one_category_fails(self):
        """Missing one of the three required categories should FAIL naming it."""
        storage_account_id = str(uuid4())
        storage_account_name = "sa1"
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    account_id=storage_account_id,
                    account_name=storage_account_name,
                    blob_properties=_make_blob_properties(),
                    blob_service_diagnostic_settings=[
                        _make_diag_setting(
                            "diag-id",
                            "diag-blob",
                            logs=[
                                _make_log(category="StorageRead"),
                                _make_log(category="StorageWrite"),
                                _make_log(category="StorageDelete", enabled=False),
                            ],
                        ),
                    ],
                )
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
            from prowler.providers.azure.services.storage.storage_blob_service_logging_enabled.storage_blob_service_logging_enabled import (
                storage_blob_service_logging_enabled,
            )

            check = storage_blob_service_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "StorageDelete" in result[0].status_extended
            # The enabled categories should NOT appear in the missing list
            assert "StorageRead" not in result[0].status_extended.split("for: ")[1]
            assert "StorageWrite" not in result[0].status_extended.split("for: ")[1]
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_missing_two_categories_fails(self):
        """Missing two of the three required categories should FAIL listing both."""
        storage_account_id = str(uuid4())
        storage_account_name = "sa1"
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    account_id=storage_account_id,
                    account_name=storage_account_name,
                    blob_properties=_make_blob_properties(),
                    blob_service_diagnostic_settings=[
                        _make_diag_setting(
                            "diag-id",
                            "diag-blob",
                            logs=[
                                _make_log(category="StorageRead"),
                            ],
                        ),
                    ],
                )
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
            from prowler.providers.azure.services.storage.storage_blob_service_logging_enabled.storage_blob_service_logging_enabled import (
                storage_blob_service_logging_enabled,
            )

            check = storage_blob_service_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            missing_part = result[0].status_extended.split("for: ")[1]
            assert "StorageDelete" in missing_part
            assert "StorageWrite" in missing_part
            assert "StorageRead" not in missing_part
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_all_logs_category_group_passes(self):
        """The allLogs category group enabled should satisfy all categories."""
        storage_account_id = str(uuid4())
        storage_account_name = "sa1"
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    account_id=storage_account_id,
                    account_name=storage_account_name,
                    blob_properties=_make_blob_properties(),
                    blob_service_diagnostic_settings=[
                        _make_diag_setting(
                            "diag-id",
                            "diag-blob",
                            logs=[
                                _make_log(
                                    category=None,
                                    category_group="allLogs",
                                    enabled=True,
                                ),
                            ],
                        ),
                    ],
                )
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
            from prowler.providers.azure.services.storage.storage_blob_service_logging_enabled.storage_blob_service_logging_enabled import (
                storage_blob_service_logging_enabled,
            )

            check = storage_blob_service_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_name == storage_account_name
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_all_logs_category_group_disabled_fails(self):
        """allLogs category group present but disabled should not count as PASS."""
        storage_account_id = str(uuid4())
        storage_account_name = "sa1"
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    account_id=storage_account_id,
                    account_name=storage_account_name,
                    blob_properties=_make_blob_properties(),
                    blob_service_diagnostic_settings=[
                        _make_diag_setting(
                            "diag-id",
                            "diag-blob",
                            logs=[
                                _make_log(
                                    category=None,
                                    category_group="allLogs",
                                    enabled=False,
                                ),
                            ],
                        ),
                    ],
                )
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
            from prowler.providers.azure.services.storage.storage_blob_service_logging_enabled.storage_blob_service_logging_enabled import (
                storage_blob_service_logging_enabled,
            )

            check = storage_blob_service_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_name == storage_account_name
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_categories_split_across_settings_passes(self):
        """Categories spread across multiple diagnostic settings should PASS."""
        storage_account_id = str(uuid4())
        storage_account_name = "sa1"
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    account_id=storage_account_id,
                    account_name=storage_account_name,
                    blob_properties=_make_blob_properties(),
                    blob_service_diagnostic_settings=[
                        _make_diag_setting(
                            "diag-id-1",
                            "diag-blob-1",
                            logs=[
                                _make_log(category="StorageRead"),
                            ],
                        ),
                        _make_diag_setting(
                            "diag-id-2",
                            "diag-blob-2",
                            logs=[
                                _make_log(category="StorageWrite"),
                                _make_log(category="StorageDelete"),
                            ],
                        ),
                    ],
                )
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
            from prowler.providers.azure.services.storage.storage_blob_service_logging_enabled.storage_blob_service_logging_enabled import (
                storage_blob_service_logging_enabled,
            )

            check = storage_blob_service_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_name == storage_account_name
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_categories_split_but_incomplete_fails(self):
        """Categories split across settings but still missing one should FAIL."""
        storage_account_id = str(uuid4())
        storage_account_name = "sa1"
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    account_id=storage_account_id,
                    account_name=storage_account_name,
                    blob_properties=_make_blob_properties(),
                    blob_service_diagnostic_settings=[
                        _make_diag_setting(
                            "diag-id-1",
                            "diag-blob-1",
                            logs=[
                                _make_log(category="StorageRead"),
                            ],
                        ),
                        _make_diag_setting(
                            "diag-id-2",
                            "diag-blob-2",
                            logs=[
                                _make_log(category="StorageWrite"),
                            ],
                        ),
                    ],
                )
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
            from prowler.providers.azure.services.storage.storage_blob_service_logging_enabled.storage_blob_service_logging_enabled import (
                storage_blob_service_logging_enabled,
            )

            check = storage_blob_service_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "StorageDelete" in result[0].status_extended
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_multiple_accounts_mixed_results(self):
        """Multiple accounts should each produce their own finding."""
        account_pass_id = str(uuid4())
        account_fail_id = str(uuid4())
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    account_id=account_pass_id,
                    account_name="sa_compliant",
                    blob_properties=_make_blob_properties(),
                    blob_service_diagnostic_settings=[
                        _make_diag_setting(
                            "diag-id",
                            "diag-blob",
                            logs=[
                                _make_log(category="StorageRead"),
                                _make_log(category="StorageWrite"),
                                _make_log(category="StorageDelete"),
                            ],
                        ),
                    ],
                ),
                _make_account(
                    account_id=account_fail_id,
                    account_name="sa_noncompliant",
                    blob_properties=_make_blob_properties(),
                    blob_service_diagnostic_settings=[],
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
            from prowler.providers.azure.services.storage.storage_blob_service_logging_enabled.storage_blob_service_logging_enabled import (
                storage_blob_service_logging_enabled,
            )

            check = storage_blob_service_logging_enabled()
            result = check.execute()

            assert len(result) == 2
            results_by_name = {r.resource_name: r for r in result}

            assert results_by_name["sa_compliant"].status == "PASS"
            assert results_by_name["sa_compliant"].resource_id == account_pass_id
            assert results_by_name["sa_compliant"].subscription == AZURE_SUBSCRIPTION_ID

            assert results_by_name["sa_noncompliant"].status == "FAIL"
            assert results_by_name["sa_noncompliant"].resource_id == account_fail_id
            assert (
                results_by_name["sa_noncompliant"].subscription == AZURE_SUBSCRIPTION_ID
            )

    def test_enabled_category_with_disabled_duplicate_passes(self):
        """An enabled category in one setting overrides disabled in another."""
        storage_account_id = str(uuid4())
        storage_account_name = "sa1"
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    account_id=storage_account_id,
                    account_name=storage_account_name,
                    blob_properties=_make_blob_properties(),
                    blob_service_diagnostic_settings=[
                        _make_diag_setting(
                            "diag-id-1",
                            "diag-blob-1",
                            logs=[
                                _make_log(category="StorageRead", enabled=False),
                                _make_log(category="StorageWrite", enabled=False),
                                _make_log(category="StorageDelete", enabled=False),
                            ],
                        ),
                        _make_diag_setting(
                            "diag-id-2",
                            "diag-blob-2",
                            logs=[
                                _make_log(category="StorageRead"),
                                _make_log(category="StorageWrite"),
                                _make_log(category="StorageDelete"),
                            ],
                        ),
                    ],
                )
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
            from prowler.providers.azure.services.storage.storage_blob_service_logging_enabled.storage_blob_service_logging_enabled import (
                storage_blob_service_logging_enabled,
            )

            check = storage_blob_service_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_all_categories_disabled_fails(self):
        """All three categories present but disabled should FAIL listing all."""
        storage_account_id = str(uuid4())
        storage_account_name = "sa1"
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    account_id=storage_account_id,
                    account_name=storage_account_name,
                    blob_properties=_make_blob_properties(),
                    blob_service_diagnostic_settings=[
                        _make_diag_setting(
                            "diag-id",
                            "diag-blob",
                            logs=[
                                _make_log(category="StorageRead", enabled=False),
                                _make_log(category="StorageWrite", enabled=False),
                                _make_log(category="StorageDelete", enabled=False),
                            ],
                        ),
                    ],
                )
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
            from prowler.providers.azure.services.storage.storage_blob_service_logging_enabled.storage_blob_service_logging_enabled import (
                storage_blob_service_logging_enabled,
            )

            check = storage_blob_service_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            missing_part = result[0].status_extended.split("for: ")[1]
            assert "StorageDelete" in missing_part
            assert "StorageRead" in missing_part
            assert "StorageWrite" in missing_part
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_subscription_name_fallback(self):
        """When subscription name is not in the map, subscription_id is used."""
        storage_account_id = str(uuid4())
        storage_account_name = "sa1"
        unknown_sub = str(uuid4())
        storage_client = mock.MagicMock()
        # Subscription not in the subscriptions map
        storage_client.subscriptions = {}
        storage_client.storage_accounts = {
            unknown_sub: [
                _make_account(
                    account_id=storage_account_id,
                    account_name=storage_account_name,
                    blob_properties=_make_blob_properties(),
                    blob_service_diagnostic_settings=[
                        _make_diag_setting(
                            "diag-id",
                            "diag-blob",
                            logs=[
                                _make_log(category="StorageRead"),
                                _make_log(category="StorageWrite"),
                                _make_log(category="StorageDelete"),
                            ],
                        ),
                    ],
                )
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
            from prowler.providers.azure.services.storage.storage_blob_service_logging_enabled.storage_blob_service_logging_enabled import (
                storage_blob_service_logging_enabled,
            )

            check = storage_blob_service_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            # Subscription name falls back to subscription_id
            assert (
                f"subscription {unknown_sub} ({unknown_sub})"
                in result[0].status_extended
            )
            assert result[0].subscription == unknown_sub

    def test_irrelevant_category_group_not_counted(self):
        """A non-allLogs category group (e.g. audit) should not satisfy the check."""
        storage_account_id = str(uuid4())
        storage_account_name = "sa1"
        storage_client = mock.MagicMock()
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    account_id=storage_account_id,
                    account_name=storage_account_name,
                    blob_properties=_make_blob_properties(),
                    blob_service_diagnostic_settings=[
                        _make_diag_setting(
                            "diag-id",
                            "diag-blob",
                            logs=[
                                _make_log(
                                    category=None,
                                    category_group="audit",
                                    enabled=True,
                                ),
                            ],
                        ),
                    ],
                )
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
            from prowler.providers.azure.services.storage.storage_blob_service_logging_enabled.storage_blob_service_logging_enabled import (
                storage_blob_service_logging_enabled,
            )

            check = storage_blob_service_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
