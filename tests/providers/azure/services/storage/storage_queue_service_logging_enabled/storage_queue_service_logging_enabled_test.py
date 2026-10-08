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

_CHECK_MODULE = (
    "prowler.providers.azure.services.storage."
    "storage_queue_service_logging_enabled."
    "storage_queue_service_logging_enabled"
)


def _make_account(
    account_id=None,
    name="teststorage",
    kind="StorageV2",
    queue_diag_settings=None,
):
    """Build a minimal Account with the fields the check requires."""
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
        private_endpoint_connections=[],
        key_expiration_period_in_days=None,
        location="westeurope",
        queue_service_diagnostic_settings=queue_diag_settings,
    )


def _make_diag_setting(logs, name="diag-queue"):
    """Build a DiagnosticSetting with the given log entries."""
    return DiagnosticSetting(
        id=f"/subscriptions/sub/providers/microsoft.insights/diagnosticSettings/{name}",
        name=name,
        storage_account_name=None,
        storage_account_id=None,
        logs=logs,
    )


class Test_storage_queue_service_logging_enabled:
    def test_no_storage_accounts(self):
        """No storage accounts in any subscription — no findings."""
        storage_client = mock.MagicMock
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                f"{_CHECK_MODULE}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_queue_service_logging_enabled.storage_queue_service_logging_enabled import (
                storage_queue_service_logging_enabled,
            )

            check = storage_queue_service_logging_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_account_kind_without_queue_skipped(self):
        """BlobStorage, BlockBlobStorage, FileStorage should produce no findings."""
        storage_client = mock.MagicMock
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(kind="BlobStorage"),
                _make_account(kind="BlockBlobStorage"),
                _make_account(kind="FileStorage"),
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                f"{_CHECK_MODULE}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_queue_service_logging_enabled.storage_queue_service_logging_enabled import (
                storage_queue_service_logging_enabled,
            )

            check = storage_queue_service_logging_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_diag_settings_none_returns_manual(self):
        """When diagnostic settings could not be read, emit MANUAL."""
        account_name = "manualaccount"
        storage_client = mock.MagicMock
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(name=account_name, queue_diag_settings=None),
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                f"{_CHECK_MODULE}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_queue_service_logging_enabled.storage_queue_service_logging_enabled import (
                storage_queue_service_logging_enabled,
            )

            check = storage_queue_service_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                "could not have its Queue service diagnostic settings evaluated"
                in result[0].status_extended
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_no_diag_settings_returns_fail(self):
        """Empty diagnostic settings list — all three categories are missing."""
        account_name = "nologsaccount"
        account_id = str(uuid4())
        storage_client = mock.MagicMock
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    account_id=account_id,
                    name=account_name,
                    queue_diag_settings=[],
                ),
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                f"{_CHECK_MODULE}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_queue_service_logging_enabled.storage_queue_service_logging_enabled import (
                storage_queue_service_logging_enabled,
            )

            check = storage_queue_service_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "StorageDelete" in result[0].status_extended
            assert "StorageRead" in result[0].status_extended
            assert "StorageWrite" in result[0].status_extended
            assert result[0].resource_id == account_id
            assert result[0].resource_name == account_name

    def test_partial_categories_returns_fail(self):
        """Only StorageRead enabled — should FAIL listing missing categories."""
        account_name = "partialaccount"
        storage_client = mock.MagicMock
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    name=account_name,
                    queue_diag_settings=[
                        _make_diag_setting(
                            logs=[
                                LogSettings(
                                    category="StorageRead",
                                    category_group=None,
                                    enabled=True,
                                ),
                            ]
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
                f"{_CHECK_MODULE}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_queue_service_logging_enabled.storage_queue_service_logging_enabled import (
                storage_queue_service_logging_enabled,
            )

            check = storage_queue_service_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "StorageDelete" in result[0].status_extended
            assert "StorageWrite" in result[0].status_extended
            assert "StorageRead" not in result[0].status_extended

    def test_all_categories_enabled_returns_pass(self):
        """All three required categories enabled in one setting — PASS."""
        account_name = "compliantaccount"
        account_id = str(uuid4())
        storage_client = mock.MagicMock
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    account_id=account_id,
                    name=account_name,
                    queue_diag_settings=[
                        _make_diag_setting(
                            logs=[
                                LogSettings(
                                    category="StorageRead",
                                    category_group=None,
                                    enabled=True,
                                ),
                                LogSettings(
                                    category="StorageWrite",
                                    category_group=None,
                                    enabled=True,
                                ),
                                LogSettings(
                                    category="StorageDelete",
                                    category_group=None,
                                    enabled=True,
                                ),
                            ]
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
                f"{_CHECK_MODULE}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_queue_service_logging_enabled.storage_queue_service_logging_enabled import (
                storage_queue_service_logging_enabled,
            )

            check = storage_queue_service_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Storage account {account_name} from subscription {AZURE_SUBSCRIPTION_DISPLAY} has Queue service logging enabled for all required categories."
            )
            assert result[0].resource_id == account_id
            assert result[0].resource_name == account_name
            assert result[0].location == "westeurope"

    def test_all_logs_category_group_returns_pass(self):
        """The allLogs category group should satisfy the requirement."""
        account_name = "alllogs"
        storage_client = mock.MagicMock
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    name=account_name,
                    queue_diag_settings=[
                        _make_diag_setting(
                            logs=[
                                LogSettings(
                                    category=None,
                                    category_group="allLogs",
                                    enabled=True,
                                ),
                            ]
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
                f"{_CHECK_MODULE}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_queue_service_logging_enabled.storage_queue_service_logging_enabled import (
                storage_queue_service_logging_enabled,
            )

            check = storage_queue_service_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_categories_split_across_settings_returns_pass(self):
        """Categories spread across multiple diagnostic settings should PASS."""
        account_name = "splitaccount"
        storage_client = mock.MagicMock
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    name=account_name,
                    queue_diag_settings=[
                        _make_diag_setting(
                            name="diag1",
                            logs=[
                                LogSettings(
                                    category="StorageRead",
                                    category_group=None,
                                    enabled=True,
                                ),
                            ],
                        ),
                        _make_diag_setting(
                            name="diag2",
                            logs=[
                                LogSettings(
                                    category="StorageWrite",
                                    category_group=None,
                                    enabled=True,
                                ),
                                LogSettings(
                                    category="StorageDelete",
                                    category_group=None,
                                    enabled=True,
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
                f"{_CHECK_MODULE}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_queue_service_logging_enabled.storage_queue_service_logging_enabled import (
                storage_queue_service_logging_enabled,
            )

            check = storage_queue_service_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_disabled_categories_returns_fail(self):
        """Categories present but disabled should result in FAIL."""
        account_name = "disabledaccount"
        storage_client = mock.MagicMock
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    name=account_name,
                    queue_diag_settings=[
                        _make_diag_setting(
                            logs=[
                                LogSettings(
                                    category="StorageRead",
                                    category_group=None,
                                    enabled=True,
                                ),
                                LogSettings(
                                    category="StorageWrite",
                                    category_group=None,
                                    enabled=False,
                                ),
                                LogSettings(
                                    category="StorageDelete",
                                    category_group=None,
                                    enabled=True,
                                ),
                            ]
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
                f"{_CHECK_MODULE}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_queue_service_logging_enabled.storage_queue_service_logging_enabled import (
                storage_queue_service_logging_enabled,
            )

            check = storage_queue_service_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "StorageWrite" in result[0].status_extended

    def test_storagev2_account_kind_produces_finding(self):
        """StorageV2 accounts should be evaluated (not skipped)."""
        storage_client = mock.MagicMock
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(kind="StorageV2", queue_diag_settings=[]),
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                f"{_CHECK_MODULE}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_queue_service_logging_enabled.storage_queue_service_logging_enabled import (
                storage_queue_service_logging_enabled,
            )

            check = storage_queue_service_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_storage_v1_account_kind_produces_finding(self):
        """Legacy Storage (v1) accounts have a Queue service and should be evaluated."""
        storage_client = mock.MagicMock
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(kind="Storage", queue_diag_settings=[]),
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                f"{_CHECK_MODULE}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_queue_service_logging_enabled.storage_queue_service_logging_enabled import (
                storage_queue_service_logging_enabled,
            )

            check = storage_queue_service_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_all_logs_category_group_disabled_returns_fail(self):
        """allLogs category group present but disabled should not satisfy the check."""
        account_name = "alllogs-disabled"
        storage_client = mock.MagicMock
        storage_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        storage_client.storage_accounts = {
            AZURE_SUBSCRIPTION_ID: [
                _make_account(
                    name=account_name,
                    queue_diag_settings=[
                        _make_diag_setting(
                            logs=[
                                LogSettings(
                                    category=None,
                                    category_group="allLogs",
                                    enabled=False,
                                ),
                            ]
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
                f"{_CHECK_MODULE}.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.azure.services.storage.storage_queue_service_logging_enabled.storage_queue_service_logging_enabled import (
                storage_queue_service_logging_enabled,
            )

            check = storage_queue_service_logging_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "StorageRead" in result[0].status_extended
            assert "StorageWrite" in result[0].status_extended
            assert "StorageDelete" in result[0].status_extended
