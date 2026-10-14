from unittest import mock

from prowler.providers.azure.services.aiservices.aiservices_service import Account
from prowler.providers.azure.services.monitor.monitor_service import (
    DiagnosticSetting,
    LogSettings,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    RESOURCE_GROUP,
    set_mocked_azure_provider,
)

CHECK = "aiservices_account_diagnostic_logging_enabled"
CHECK_PATH = f"prowler.providers.azure.services.aiservices.{CHECK}.{CHECK}"
ACCOUNT_ID = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.CognitiveServices/accounts/openai1"
PREFIX = f"AI services account openai1 (kind OpenAI) from subscription {AZURE_SUBSCRIPTION_DISPLAY}"


def build_setting(*logs: LogSettings) -> DiagnosticSetting:
    return DiagnosticSetting(
        id=f"{ACCOUNT_ID}/providers/microsoft.insights/diagnosticSettings/diag1",
        storage_account_id=None,
        storage_account_name=None,
        logs=list(logs),
        name="diag1",
        workspace_id="/subscriptions/x/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law1",
    )


def build_account(settings) -> Account:
    return Account(
        id=ACCOUNT_ID,
        name="openai1",
        location="eastus",
        kind="OpenAI",
        public_network_access=False,
        disable_local_auth=True,
        encryption_key_source="Microsoft.CognitiveServices",
        monitor_diagnostic_settings=settings,
    )


def run_check(accounts):
    aiservices_client = mock.MagicMock()
    aiservices_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
    aiservices_client.accounts = accounts
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ),
        mock.patch(f"{CHECK_PATH}.aiservices_client", new=aiservices_client),
    ):
        from prowler.providers.azure.services.aiservices.aiservices_account_diagnostic_logging_enabled.aiservices_account_diagnostic_logging_enabled import (
            aiservices_account_diagnostic_logging_enabled,
        )

        return aiservices_account_diagnostic_logging_enabled().execute()


def single(settings):
    return run_check({AZURE_SUBSCRIPTION_ID: {ACCOUNT_ID: build_account(settings)}})


class Test_aiservices_account_diagnostic_logging_enabled:
    def test_no_resources(self):
        result = run_check({})
        assert len(result) == 0

    def test_settings_unreadable_is_manual(self):
        result = single(None)
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"{PREFIX} diagnostic settings could not be read; grant Microsoft.Insights/diagnosticSettings/read (included in Reader) to evaluate audit logging."
        )
        assert result[0].resource_id == ACCOUNT_ID
        assert result[0].resource_name == "openai1"
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_no_diagnostic_settings(self):
        result = single([])
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"{PREFIX} has no diagnostic setting that sends audit logs."
        )
        assert result[0].resource_id == ACCOUNT_ID
        assert result[0].resource_name == "openai1"
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_audit_category_disabled(self):
        result = single([build_setting(LogSettings("Audit", None, False))])
        assert result[0].status == "FAIL"

    def test_only_request_response_category(self):
        result = single([build_setting(LogSettings("RequestResponse", None, True))])
        assert result[0].status == "FAIL"

    def test_audit_category_enabled(self):
        result = single(
            [
                build_setting(
                    LogSettings("RequestResponse", None, True),
                    LogSettings("Audit", None, True),
                )
            ]
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"{PREFIX} has a diagnostic setting that sends audit logs."
        )
        assert result[0].resource_id == ACCOUNT_ID
        assert result[0].resource_name == "openai1"
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_audit_category_group_enabled(self):
        result = single([build_setting(LogSettings(None, "audit", True))])
        assert result[0].status == "PASS"

    def test_all_logs_category_group_enabled(self):
        result = single([build_setting(LogSettings(None, "allLogs", True))])
        assert result[0].status == "PASS"

    def test_category_group_case_insensitive(self):
        result = single([build_setting(LogSettings(None, "alllogs", True))])
        assert result[0].status == "PASS"

    def test_second_setting_sends_audit_logs(self):
        result = single(
            [
                build_setting(),
                build_setting(LogSettings(None, "audit", True)),
            ]
        )
        assert result[0].status == "PASS"
